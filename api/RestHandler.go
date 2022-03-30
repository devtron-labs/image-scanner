package api

import (
	"encoding/json"
	"net/http"

	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/pkg/grafeasService"
	"github.com/devtron-labs/image-scanner/pkg/klarService"
	"github.com/devtron-labs/image-scanner/pkg/security"
	"github.com/devtron-labs/image-scanner/pkg/user"
	"github.com/devtron-labs/image-scanner/pubsub"
	"go.uber.org/zap"
)

type RestHandler interface {
	TestApplication(w http.ResponseWriter, r *http.Request)
	TestApplicationList(w http.ResponseWriter, r *http.Request)
	ScanForVulnerability(w http.ResponseWriter, r *http.Request)
}

func NewRestHandlerImpl(logger *zap.SugaredLogger,
	klarService klarService.KlarService, testPublish pubsub.TestPublish,
	grafeasService grafeasService.GrafeasService,
	userService user.UserService, imageScanService security.ImageScanService) *RestHandlerImpl {
	return &RestHandlerImpl{
		logger:           logger,
		klarService:      klarService,
		testPublish:      testPublish,
		grafeasService:   grafeasService,
		userService:      userService,
		imageScanService: imageScanService,
	}
}

type RestHandlerImpl struct {
	logger           *zap.SugaredLogger
	klarService      klarService.KlarService
	testPublish      pubsub.TestPublish
	grafeasService   grafeasService.GrafeasService
	userService      user.UserService
	imageScanService security.ImageScanService
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
	result, err := impl.klarService.Process(&scanConfig)
	if err != nil {
		impl.logger.Errorw("err in process msg", "err", err)
		impl.writeJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	impl.logger.Debugw("save", "status", result)
	impl.writeJsonResp(w, err, result, 200)
}
