package klarService

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/internal/sql/repository"
	"github.com/devtron-labs/image-scanner/pkg/security"
	"github.com/go-pg/pg"
	"strings"

	"errors"
	"github.com/caarlos0/env"
	/*"github.com/devtron-labs/image-scanner/client"*/
	/*"github.com/devtron-labs/image-scanner/client"*/
	"github.com/devtron-labs/image-scanner/pkg/grafeasService"
	"github.com/optiopay/klar/clair"
	"github.com/optiopay/klar/docker"
	"go.uber.org/zap"
	"golang.org/x/oauth2/google"
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
	logger                        *zap.SugaredLogger
	klarConfig                    *KlarConfig
	grafeasService                grafeasService.GrafeasService
	userRepository                repository.UserRepository
	imageScanService              security.ImageScanService
	dockerArtifactStoreRepository repository.DockerArtifactStoreRepository
}

func NewKlarServiceImpl(logger *zap.SugaredLogger, klarConfig *KlarConfig, grafeasService grafeasService.GrafeasService,
	userRepository repository.UserRepository, imageScanService security.ImageScanService,
	dockerArtifactStoreRepository repository.DockerArtifactStoreRepository) *KlarServiceImpl {
	return &KlarServiceImpl{
		logger:                        logger,
		klarConfig:                    klarConfig,
		grafeasService:                grafeasService,
		userRepository:                userRepository,
		imageScanService:              imageScanService,
		dockerArtifactStoreRepository: dockerArtifactStoreRepository,
	}
}

func (impl *KlarServiceImpl) Process(scanEvent *common.ScanEvent) (*common.ScanEventResponse, error) {
	scanEventResponse := &common.ScanEventResponse{
		RequestData: scanEvent,
	}
	dockerRegistry, err := impl.dockerArtifactStoreRepository.FindById(scanEvent.DockerRegistryId)
	if err != nil {
		impl.logger.Errorw("error in getting docker registry by id", "err", err, "id", scanEvent.DockerRegistryId)
		return nil, err
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
	tokenGcr := ""
	config := &docker.Config{
		ImageName: scanEvent.Image,
		User:      dockerRegistry.Username,
		Password:  dockerRegistry.Password,
		//InsecureRegistry: true,
		//InsecureTLS:      true,
		Timeout: 4 * time.Minute,
	}
	impl.logger.Debugw("config", "config", config)
	if dockerRegistry.RegistryType == repository.REGISTRYTYPE_ECR {
		var sess *session.Session
		sess, err = session.NewSession(&aws.Config{
			Region:      aws.String(dockerRegistry.AWSRegion),
			Credentials: credentials.NewStaticCredentials(dockerRegistry.AWSAccessKeyId, dockerRegistry.AWSSecretAccessKey, ""),
		})

		// Create a ECR client with additional configuration
		svc := ecr.New(sess, aws.NewConfig().WithRegion(dockerRegistry.AWSRegion))
		token, err := svc.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
		if err != nil {
			impl.logger.Errorw("error in getting auth token from ecr", "err", err)
			return nil, err
		}
		config.Token = *token.AuthorizationData[0].AuthorizationToken
	} else if dockerRegistry.Username == "_json_key" {
		lenPassword := len(dockerRegistry.Password)
		if lenPassword > 1 {
			dockerRegistry.Password = strings.TrimPrefix(dockerRegistry.Password, "'")
			dockerRegistry.Password = strings.TrimSuffix(dockerRegistry.Password, "'")
		}
		jwtToken, err := google.JWTAccessTokenSourceWithScope([]byte(dockerRegistry.Password), "")
		if err != nil {
			impl.logger.Errorw("error in getting token from json key file-gcr", "err", err)
			return nil, err
		}
		token, err := jwtToken.Token()
		if err != nil {
			impl.logger.Errorw("error in getting token from jwt token", "err", err)
			return nil, err
		}
		tokenGcr = fmt.Sprintf(token.TokenType + " " + token.AccessToken)
	}
	image, err := docker.NewImage(config)
	if err != nil {
		impl.logger.Errorw("Can't parse name", "err", err)
		return scanEventResponse, err
	}
	if tokenGcr != "" {
		//setting token here because docker.NewImage sets the token as basic and in gcp it's bearer in most of the cases
		image.Token = tokenGcr
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
