/*
 * Copyright (c) 2024. Devtron Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package api

import (
	"encoding/json"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/pkg/clairService"
	"github.com/devtron-labs/image-scanner/pkg/grafeasService"
	"github.com/devtron-labs/image-scanner/pkg/klarService"
	"github.com/devtron-labs/image-scanner/pkg/security"
	"github.com/devtron-labs/image-scanner/pkg/sql/bean"
	"github.com/devtron-labs/image-scanner/pkg/user"
	"github.com/devtron-labs/image-scanner/pubsub"
	"go.uber.org/zap"
	"net/http"
	"os"
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
	imageScanConfig *security.ImageScanConfig) *RestHandlerImpl {
	return &RestHandlerImpl{
		logger:           logger,
		testPublish:      testPublish,
		grafeasService:   grafeasService,
		userService:      userService,
		imageScanService: imageScanService,
		klarService:      klarService,
		clairService:     clairService,
		imageScanConfig:  imageScanConfig,
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
	imageScanConfig  *security.ImageScanConfig
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
	if scanConfig.UserId == 0 {
		scanConfig.UserId = 1 //setting user as system user in case of empty user data
	}
	impl.logger.Infow("image scan req", "req", scanConfig)
	var result *common.ScanEventResponse
	tool, err := impl.imageScanService.GetActiveTool()
	if err != nil {
		impl.logger.Errorw("err in image scanning", "err", err)
		writeJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	executionHistory, executionHistoryDirPath, err := impl.imageScanService.RegisterScanExecutionHistoryAndState(&scanConfig, tool)
	if err != nil {
		impl.logger.Errorw("service err, RegisterScanExecutionHistoryAndState", "err", err)
		writeJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	imageToBeScanned, err := impl.imageScanService.GetImageToBeScannedAndFetchCliEnv(&scanConfig)
	if err != nil {
		impl.logger.Errorw("service err, GetImageToBeScanned", "err", err)
		writeJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	scanConfig.Image = imageToBeScanned
	if tool.Name == bean.ScanToolClair && tool.Version == bean.ScanToolVersion2 {
		result, err = impl.klarService.Process(&scanConfig, executionHistory)
		if err != nil {
			impl.logger.Errorw("err in process msg", "err", err)
			writeJsonResp(w, err, nil, http.StatusInternalServerError)
			return
		}
	} else if tool.Name == bean.ScanToolClair && tool.Version == bean.ScanToolVersion4 {
		result, err = impl.clairService.ScanImage(&scanConfig, tool, executionHistory)
		if err != nil {
			impl.logger.Errorw("err in process msg", "err", err)
			writeJsonResp(w, err, nil, http.StatusInternalServerError)
			return
		}
	} else {
		err = impl.imageScanService.ScanImage(&scanConfig, tool, executionHistory, executionHistoryDirPath)
		if err != nil {
			impl.logger.Errorw("err in process msg", "err", err)
			writeJsonResp(w, err, nil, http.StatusInternalServerError)
			return
		}
	}
	//deleting executionDirectoryPath with files as well
	err = os.RemoveAll(executionHistoryDirPath)
	if err != nil {
		impl.logger.Errorw("error in deleting executionHistoryDirectory", "err", err)
		writeJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}

	impl.logger.Debugw("save", "status", result)
	writeJsonResp(w, err, result, http.StatusOK)
}
