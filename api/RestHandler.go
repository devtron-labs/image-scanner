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
	TestApplication(w http.ResponseWriter, r *http.Request)
	TestApplicationList(w http.ResponseWriter, r *http.Request)
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

func (impl RestHandlerImpl) writeJsonResp(w http.ResponseWriter, err error, respBody interface{}, status int) {
	response := Response{}
	response.Code = status
	response.Status = http.StatusText(status)
	if err == nil {
		response.Result = respBody
	} else {
		apiErr := &ApiError{}
		apiErr.Code = "000" // 000=unknown
		apiErr.InternalMessage = err.Error()
		apiErr.UserMessage = respBody
		response.Errors = []*ApiError{apiErr}

	}
	b, err := json.Marshal(response)
	if err != nil {
		impl.logger.Error("error in marshaling err object", err)
		status = 500
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}

type ResetRequest struct {
	AppId         int `json:"appId"`
	EnvironmentId int `json:"environmentId"`
}

func (impl *RestHandlerImpl) TestApplication(w http.ResponseWriter, r *http.Request) {
	scanConfig := &common.ScanEvent{}
	scanConfig.Image = "quay.io/coreos/clair:v2.0.0"
	//err := impl.klarService.Process(scanConfig)
	err := impl.testPublish.PublishForScan(pubsub.TOPIC_CI_SCAN, scanConfig)
	if err != nil {
		impl.logger.Errorw("err in process msg", "err", err)
		impl.writeJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	impl.logger.Debugw("save", "status", "")
	impl.writeJsonResp(w, err, nil, 200)
}

func (impl *RestHandlerImpl) TestApplicationList(w http.ResponseWriter, r *http.Request) {
	scanConfig := &common.ScanEvent{}
	scanConfig.Image = "quay.io/coreos/clair:v2.0.0"
	noteResp, err := impl.grafeasService.GetNotesById("CVE-2016-9840")
	if err != nil {
		impl.logger.Errorw("err in process msg", "err", err)
		impl.writeJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	impl.logger.Debugw("resp from get note api", "noteResp", noteResp)
	impl.writeJsonResp(w, err, noteResp, 200)
}

func (impl *RestHandlerImpl) ScanForVulnerability(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var scanConfig common.ScanEvent
	err := decoder.Decode(&scanConfig)
	if err != nil {
		impl.logger.Errorw("error in decode request", "error", err)
		writeJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	//scanConfig.Image = "quay.io/coreos/clair:v2.0.0"
	if scanConfig.UserId == 0 {
		scanConfig.UserId = 1
	}
	impl.logger.Infow("image scan req", "req", scanConfig)
	var result *common.ScanEventResponse

	if impl.scannerConfig.ScannerType == SCANNER_TYPE_CLAIR_V2 {
		result, err = impl.klarService.Process(&scanConfig)
		if err != nil {
			impl.logger.Errorw("err in process msg", "err", err)
			impl.writeJsonResp(w, err, nil, http.StatusInternalServerError)
			return
		}
	} else if impl.scannerConfig.ScannerType == SCANNER_TYPE_CLAIR_V4 {
		result, err = impl.clairService.ScanImage(&scanConfig)
		if err != nil {
			impl.logger.Errorw("err in process msg", "err", err)
			impl.writeJsonResp(w, err, nil, http.StatusInternalServerError)
			return
		}
	}

	impl.logger.Debugw("save", "status", result)
	impl.writeJsonResp(w, err, result, 200)
}
func GetScannerConfig() (*ScannerConfig, error) {
	scannerConfig := &ScannerConfig{}
	err := env.Parse(scannerConfig)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("could not get scanner config from environment :%v", err))
	}
	return scannerConfig, err
}
