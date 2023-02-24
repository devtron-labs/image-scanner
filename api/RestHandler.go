package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/caarlos0/env"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/pkg/clairService"
	"github.com/devtron-labs/image-scanner/pkg/grafeasService"
	"github.com/devtron-labs/image-scanner/pkg/klarService"
	"github.com/devtron-labs/image-scanner/pkg/security"
	"github.com/devtron-labs/image-scanner/pkg/user"
	"github.com/devtron-labs/image-scanner/pubsub"
	"go.uber.org/zap"
	"net/http"
)

type RestHandler interface {
	ScanForVulnerability(w http.ResponseWriter, r *http.Request)
}

func NewRestHandlerImpl(logger *zap.SugaredLogger,
	testPublish pubsub.TestPublish,
	grafeasService grafeasService.GrafeasService,
	userService user.UserService, imageScanService security.ImageScanService,
	klarService klarService.KlarService,
	clairService clairService.ClairService,
	scannerConfig *ScannerConfig) *RestHandlerImpl {
	return &RestHandlerImpl{
		logger:           logger,
		testPublish:      testPublish,
		grafeasService:   grafeasService,
		userService:      userService,
		imageScanService: imageScanService,
		klarService:      klarService,
		clairService:     clairService,
		scannerConfig:    scannerConfig,
	}
}

type RestHandlerImpl struct {
	logger           *zap.SugaredLogger
	testPublish      pubsub.TestPublish
	grafeasService   grafeasService.GrafeasService
	userService      user.UserService
	imageScanService security.ImageScanService
	klarService      klarService.KlarService
	clairService     clairService.ClairService
	scannerConfig    *ScannerConfig
}
type Response struct {
	Code   int         `json:"code,omitempty"`
	Status string      `json:"status,omitempty"`
	Result interface{} `json:"result,omitempty"`
	Errors []*ApiError `json:"errors,omitempty"`
}
type ApiError struct {
	HttpStatusCode    int         `json:"-"`
	Code              string      `json:"code,omitempty"`
	InternalMessage   string      `json:"internalMessage,omitempty"`
	UserMessage       interface{} `json:"userMessage,omitempty"`
	UserDetailMessage string      `json:"userDetailMessage,omitempty"`
}

type ScannerConfig struct {
	ScannerType string `env:"SCANNER_TYPE" envDefault:"CLAIRV4"`
}

const (
	SCANNER_TYPE_CLAIR_V4 = "CLAIRV4"
	SCANNER_TYPE_CLAIR_V2 = "CLAIRV2"
	SCANNER_TYPE_TRIVY    = "TRIVY"
)

func GetScannerConfig() (*ScannerConfig, error) {
	scannerConfig := &ScannerConfig{}
	err := env.Parse(scannerConfig)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("could not get scanner config from environment :%v", err))
	}
	return scannerConfig, err
}

type ResetRequest struct {
	AppId         int `json:"appId"`
	EnvironmentId int `json:"environmentId"`
}

func (impl *RestHandlerImpl) ScanForVulnerability(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var scanConfig common.ImageScanEvent
	err := decoder.Decode(&scanConfig)
	if err != nil {
		impl.logger.Errorw("error in decode request", "error", err)
		writeJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	if scanConfig.UserId == 0 {
		scanConfig.UserId = 1 //setting user as system user in case of empty user data
	}
	impl.logger.Infow("image scan req", "req", scanConfig)
	var result *common.ScanEventResponse
	if impl.scannerConfig.ScannerType == SCANNER_TYPE_CLAIR_V2 {
		result, err = impl.klarService.Process(&scanConfig)
		if err != nil {
			impl.logger.Errorw("err in process msg", "err", err)
			writeJsonResp(w, err, nil, http.StatusInternalServerError)
			return
		}
	} else if impl.scannerConfig.ScannerType == SCANNER_TYPE_CLAIR_V4 {
		result, err = impl.clairService.ScanImage(&scanConfig)
		if err != nil {
			impl.logger.Errorw("err in process msg", "err", err)
			writeJsonResp(w, err, nil, http.StatusInternalServerError)
			return
		}
	}

	impl.logger.Debugw("save", "status", result)
	writeJsonResp(w, err, result, http.StatusOK)
}
