package api

import (
	"encoding/json"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/internal/sql/bean"
	"github.com/devtron-labs/image-scanner/pkg/clairService"
	"github.com/devtron-labs/image-scanner/pkg/grafeasService"
	"github.com/devtron-labs/image-scanner/pkg/klarService"
	"github.com/devtron-labs/image-scanner/pkg/security"
	"github.com/devtron-labs/image-scanner/pkg/user"
	//"github.com/devtron-labs/image-scanner/pubsub"
	"go.uber.org/zap"
	"net/http"
	"os"
)

type RestHandler interface {
	ScanForVulnerability(w http.ResponseWriter, r *http.Request)
}

func NewRestHandlerImpl(logger *zap.SugaredLogger,
	//testPublish pubsub.TestPublish,
	grafeasService grafeasService.GrafeasService,
	userService user.UserService, imageScanService security.ImageScanService,
	klarService klarService.KlarService,
	clairService clairService.ClairService,
	imageScanConfig *security.ImageScanConfig,
	codeScanService security.CodeScanService,
) *RestHandlerImpl {
	return &RestHandlerImpl{
		logger: logger,
		//testPublish:      testPublish,
		grafeasService:   grafeasService,
		userService:      userService,
		imageScanService: imageScanService,
		klarService:      klarService,
		clairService:     clairService,
		imageScanConfig:  imageScanConfig,
		codeScanService:  codeScanService,
	}
}

type RestHandlerImpl struct {
	logger *zap.SugaredLogger
	//testPublish      pubsub.TestPublish
	grafeasService   grafeasService.GrafeasService
	userService      user.UserService
	imageScanService security.ImageScanService
	klarService      klarService.KlarService
	clairService     clairService.ClairService
	imageScanConfig  *security.ImageScanConfig
	codeScanService  security.CodeScanService
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
	result, err := impl.ScanForVulnerabilityEvent(&scanConfig)
	if err != nil {
		writeJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	impl.logger.Debugw("save", "status", result)
	writeJsonResp(w, err, result, http.StatusOK)
}

func (impl *RestHandlerImpl) ScanForVulnerabilityEvent(scanConfig *common.ImageScanEvent) (*common.ScanEventResponse, error) {

	if scanConfig.UserId == 0 {
		scanConfig.UserId = 1 //setting user as system user in case of empty user data
	}
	impl.logger.Infow("image scan req", "req", scanConfig)
	var result *common.ScanEventResponse
	tool, err := impl.imageScanService.GetActiveTool()
	if err != nil {
		impl.logger.Errorw("err in image scanning", "err", err)
		return nil, err
	}
	executionHistory, executionHistoryDirPath, err := impl.imageScanService.RegisterScanExecutionHistoryAndState(scanConfig, tool)
	if err != nil {
		impl.logger.Errorw("service err, RegisterScanExecutionHistoryAndState", "err", err)
		return nil, err
	}

	if scanConfig.SourceType == common.SourceTypeCode {
		err = impl.codeScanService.ScanCode(scanConfig, tool, executionHistory, executionHistoryDirPath)
		if err != nil {
			impl.logger.Errorw("Error scanning code", "err", err)

		}
	} else {
		if tool.Name == bean.ScanToolClair && tool.Version == bean.ScanToolVersion2 {
			result, err = impl.klarService.Process(scanConfig, executionHistory)
			if err != nil {
				impl.logger.Errorw("err in process msg", "err", err)
				return nil, err
			}
		} else if tool.Name == bean.ScanToolClair && tool.Version == bean.ScanToolVersion4 {
			result, err = impl.clairService.ScanImage(scanConfig, tool, executionHistory)
			if err != nil {
				impl.logger.Errorw("err in process msg", "err", err)
				return nil, err
			}
		} else {
			err = impl.imageScanService.ScanImage(scanConfig, tool, executionHistory, executionHistoryDirPath)
			if err != nil {
				impl.logger.Errorw("err in process msg", "err", err)
				return nil, err
			}
		}
	}

	//deleting executionDirectoryPath with files as well
	err = os.RemoveAll(executionHistoryDirPath)
	if err != nil {
		impl.logger.Errorw("error in deleting executionHistoryDirectory", "err", err)
		return nil, err
	}
	return result, nil
}
