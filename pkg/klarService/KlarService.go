package klarService

import (
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/internal/sql/repository"
	"github.com/devtron-labs/image-scanner/pkg/security"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/go-pg/pg"

	/*"github.com/devtron-labs/image-scanner/client"*/
	/*"github.com/devtron-labs/image-scanner/client"*/
	"github.com/devtron-labs/image-scanner/pkg/grafeasService"
	"errors"
	"github.com/caarlos0/env"
	"github.com/optiopay/klar/clair"
	"github.com/optiopay/klar/docker"
	"go.uber.org/zap"
	"time"
)

type KlarConfig struct {
	//LayerCount      int    `env:"CLUSTER_ID" envDefault:"0"`
	ClairAddr string `env:"CLAIR_ADDR" envDefault:"http://localhost:6060"`
	//CLAIR_OUTPUT    string `env:"CLAIR_OUTPUT" envDefault:"localhost:High"`
	//CLAIR_THRESHOLD string `env:"CLAIR_THRESHOLD" envDefault:"localhost:10"`
	ClairTimeout int `env:"CLAIR_TIMEOUT" envDefault:"30"`
	//DOCKER_TIMEOUT  string `env:"DOCKER_TIMEOUT" envDefault:"5"`
	JSONOutput bool `env:"JSON_OUTPUT" envDefault:"true"`
}

func GetKlarConfig() (*KlarConfig, error) {
	cfg := &KlarConfig{}
	err := env.Parse(cfg)
	if err != nil {
		return nil, errors.New("could not get event service url")
	}
	return cfg, err
}

type KlarService interface {
	Process(scanEvent *common.ScanEvent) (*common.ScanEventResponse, error)
}

type KlarServiceImpl struct {
	logger           *zap.SugaredLogger
	klarConfig       *KlarConfig
	grafeasService   grafeasService.GrafeasService
	repository       repository.UserRepository
	imageScanService security.ImageScanService
}

func NewKlarServiceImpl(logger *zap.SugaredLogger, klarConfig *KlarConfig, grafeasService grafeasService.GrafeasService,
	repository repository.UserRepository, imageScanService security.ImageScanService) *KlarServiceImpl {
	return &KlarServiceImpl{
		logger:           logger,
		klarConfig:       klarConfig,
		grafeasService:   grafeasService,
		repository:       repository,
		imageScanService: imageScanService,
	}
}

func (impl *KlarServiceImpl) Process(scanEvent *common.ScanEvent) (*common.ScanEventResponse, error) {
	scanEventResponse := &common.ScanEventResponse{
		RequestData: scanEvent,
	}

	scanned, err := impl.imageScanService.IsImageScanned(scanEvent.Image)
	if err != nil && err != pg.ErrNoRows {
		impl.logger.Errorw("error in fetching scan history ", "err", err)
		return nil, err
	}
	if scanned {
		impl.logger.Infow("image already scanned", "image", scanEvent.Image)
		return scanEventResponse, nil
	}

	var sess *session.Session
	if (len(scanEvent.AccessKey) > 0 && len(scanEvent.SecretKey) > 0) || len(scanEvent.Token) > 0 {
		sess, err = session.NewSession(&aws.Config{
			Region:      aws.String(scanEvent.AwsRegion),
			Credentials: credentials.NewStaticCredentials(scanEvent.AccessKey, scanEvent.SecretKey, scanEvent.Token),
		})
	}

	// Create a ECR client with additional configuration
	tokenData := ""
	tokens := &tokenData
	if (len(scanEvent.AccessKey) > 0 && len(scanEvent.SecretKey) > 0) || len(scanEvent.Token) > 0 {
		svc := ecr.New(sess, aws.NewConfig().WithRegion(scanEvent.AwsRegion))
		token, err := svc.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
		if err != nil {
			return nil, err
		}
		tokens = token.AuthorizationData[0].AuthorizationToken
		/*decoded, err := base64.StdEncoding.DecodeString(*tokens)
		if err != nil {
			fmt.Println("decode error:", err)
			return nil, err
		}
		fmt.Println(string(decoded))*/
	}
	config := &docker.Config{
		ImageName: scanEvent.Image,
		//User:      "AWS",
		//Password:  string(decoded),
		//InsecureRegistry: true,
		//InsecureTLS:      true,
		Token:   *tokens,
		Timeout: 4 * time.Minute,
	}
	impl.logger.Debugw("config", "config", config)
	image, err := docker.NewImage(config)
	if err != nil {
		impl.logger.Errorw("Can't parse name", "err", err)
		return scanEventResponse, err
	}

	err = image.Pull()
	if err != nil {
		impl.logger.Errorw("Can't pull image ", "err", err)
		return scanEventResponse, err
	}
	impl.logger.Debugw("image pull", "layers count", len(image.FsLayers))
	output := jsonOutput{
		Vulnerabilities: make(map[string][]*clair.Vulnerability),
	}

	if len(image.FsLayers) == 0 {
		impl.logger.Error("Can't pull fsLayers")
		return scanEventResponse, errors.New("can't pull fsLayers")
	} else {
		if impl.klarConfig.JSONOutput {
			output.LayerCount = len(image.FsLayers)
		} else {
			impl.logger.Debugw("Analysing layers ", "layers", len(image.FsLayers))
		}
	}

	var vs []*clair.Vulnerability
	for _, ver := range []int{1, 3} {
		c := clair.NewClair(impl.klarConfig.ClairAddr, ver, time.Duration(5*time.Minute))
		vs, err = c.Analyse(image)
		if err != nil {
			impl.logger.Errorw("Failed to analyze using API", "ver", ver, "err", err)
		} else {
			if !impl.klarConfig.JSONOutput {
				impl.logger.Debugw("Got results from Clair API ", "ver", ver)
			}
			break
		}
	}
	if err != nil {
		impl.logger.Errorw("Failed to analyze, exiting", "err", err)
		return scanEventResponse, err
	}
	/*_, err = impl.grafeasService.CreateNote(vs, scanEvent)
	if err != nil {
		impl.logger.Errorw("Failed to post save to grafeas", "err", err)
	}*/

	vulnerabilities, err := impl.imageScanService.CreateScanExecutionRegistry(vs, scanEvent)
	if err != nil {
		impl.logger.Errorw("Failed dump scanned data", "err", err)
		return scanEventResponse, err
	}
	scanEventResponse.ResponseData = vulnerabilities

	return scanEventResponse, nil
}

type jsonOutput struct {
	LayerCount      int
	Vulnerabilities map[string][]*clair.Vulnerability
}
