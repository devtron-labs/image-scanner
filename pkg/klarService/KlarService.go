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
	impl.logger.Infow("got docker registry", "dockerRegistry", dockerRegistry)
	scanned, err := impl.imageScanService.IsImageScanned(scanEvent.Image)
	impl.logger.Infow("isImageScanned results", "scanned", scanned, "err", err)
	if err != nil && err != pg.ErrNoRows {
		impl.logger.Errorw("error in fetching scan history ", "err", err)
		return nil, err
	}
	if scanned {
		impl.logger.Infow("image already scanned", "image", scanEvent.Image)
		return scanEventResponse, nil
	}
	tokenData := ""
	tokenGcr := ""
	tokens := &tokenData
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
			return nil, err
		}
		tokens = token.AuthorizationData[0].AuthorizationToken
		/*decoded, err := base64.StdEncoding.DecodeString(*tokens)
		if err != nil {
			fmt.Println("decode error:", err)
			return nil, err
		}
		fmt.Println(string(decoded))*/
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
	config := &docker.Config{
		ImageName: scanEvent.Image,
		User:      dockerRegistry.Username,
		Password:  dockerRegistry.Password,
		//InsecureRegistry: true,
		//InsecureTLS:      true,
		Token:   *tokens,
		Timeout: 4 * time.Minute,
	}
	impl.logger.Infow("got config for dockerNewImage", "config", config)
	impl.logger.Debugw("config", "config", config)
	image, err := docker.NewImage(config)
	if err != nil {
		impl.logger.Errorw("Can't parse name", "err", err)
		return scanEventResponse, err
	}
	impl.logger.Infow("got docker image entity", "image", image)
	if tokenGcr != "" {
		//setting token here because docker.NewImage sets the token as basic and in gcp it's bearer in most of the cases
		image.Token = tokenGcr
	}
	err = image.Pull()
	if err != nil {
		impl.logger.Errorw("Can't pull image ", "err", err)
		return scanEventResponse, err
	}
	impl.logger.Infow("pulled image successfully", "image", image)
	impl.logger.Debugw("image pull", "layers count", len(image.FsLayers))
	output := jsonOutput{
		Vulnerabilities: make(map[string][]*clair.Vulnerability),
	}

	if len(image.FsLayers) == 0 {
		impl.logger.Error("Can't pull fsLayers")
		return scanEventResponse, errors.New("can't pull fsLayers")
	} else {
		impl.logger.Infow("checking klarConfig.jsonOutput", "klarConfig", impl.klarConfig)
		if impl.klarConfig.JSONOutput {
			output.LayerCount = len(image.FsLayers)
		} else {
			impl.logger.Debugw("Analysing layers ", "layers", len(image.FsLayers))
		}
	}
	impl.logger.Infow("output = jsonOutput", "output", output,"klarConfig",impl.klarConfig)
	var vs []*clair.Vulnerability
	for _, ver := range []int{2, 3} {
		c := clair.NewClair(impl.klarConfig.ClairAddr, ver, time.Duration(5*time.Minute))
		impl.logger.Infow("getting new clair", "clair", c, "ver", ver)
		vs, err = c.Analyse(image)
		impl.logger.Infow("anaylyse image results", "vs", vs, "err", err, "ver", ver)
		if err != nil {
			impl.logger.Errorw("Failed to analyze using API", "ver", ver, "err", err)
		} else {
			if !impl.klarConfig.JSONOutput {
				impl.logger.Infow("got results from clair api", "vs", vs, "err", err, "ver", ver,"klarConfig",impl.klarConfig)
				impl.logger.Debugw("Got results from Clair API ", "ver", ver)
			}
			impl.logger.Infow("breaking from image analysing", "vs", vs, "err", err, "ver", ver,"klarConfig",impl.klarConfig)
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
	impl.logger.Infow("createScanExecutionRegistry", "vs", vs, "scanEvent", scanEvent)
	vulnerabilities, err := impl.imageScanService.CreateScanExecutionRegistry(vs, scanEvent)
	if err != nil {
		impl.logger.Errorw("Failed dump scanned data", "err", err)
		return scanEventResponse, err
	}
	scanEventResponse.ResponseData = vulnerabilities
	impl.logger.Infow("returning response", "scanEventResponse", scanEventResponse)
	return scanEventResponse, nil
}

type jsonOutput struct {
	LayerCount      int
	Vulnerabilities map[string][]*clair.Vulnerability
}
