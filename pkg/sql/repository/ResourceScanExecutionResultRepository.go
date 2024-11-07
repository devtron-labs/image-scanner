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

package repository

import (
	"github.com/go-pg/pg"
	"go.uber.org/zap"
)

type ResourceScanResult struct {
	tableName                   struct{}           `sql:"resource_scan_execution_result" pg:",discard_unknown_columns"`
	Id                          int                `sql:"id,pk"`
	ImageScanExecutionHistoryId int                `sql:"image_scan_execution_history_id"`
	ScanDataJson                string             `sql:"scan_data_json"`
	Format                      ResourceScanFormat `sql:"format"`
	Types                       []int              `sql:"types" pg:",array"`
	ScanToolId                  int                `sql:"scan_tool_id"`
}

type ResourceScanFormat int

const (
	CycloneDxSbom ResourceScanFormat = 1 //SBOM
	TrivyJson                        = 2
	Json                             = 3
)

type ResourceScanType int

const (
	Vulnerabilities ResourceScanType = 1
	License         ResourceScanType = 2
	Config          ResourceScanType = 3
	Secrets         ResourceScanType = 4
)

func (t ResourceScanType) ToInt() int {
	return int(t)
}

type ResourceScanResultRepository interface {
	SaveInBatch(models []*ResourceScanResult) error
	FetchByScanHistoryIdAndFormatType(scanHistoryId int, format int) ([]*ResourceScanResult, error)
}

type ResourceScanResultRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewResourceScanResultRepositoryImpl(dbConnection *pg.DB, logger *zap.SugaredLogger) *ResourceScanResultRepositoryImpl {
	return &ResourceScanResultRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}

func (impl ResourceScanResultRepositoryImpl) SaveInBatch(models []*ResourceScanResult) error {
	return impl.dbConnection.Insert(&models)
}

func (impl ResourceScanResultRepositoryImpl) FetchByScanHistoryIdAndFormatType(scanHistoryId int, format int) ([]*ResourceScanResult, error) {
	var model []*ResourceScanResult
	err := impl.dbConnection.Model(&model).
		Where("image_scan_execution_history_id = ?", scanHistoryId).
		Where("format = ?", format).
		Select()
	if err != nil {
		return model, err
	}

	return model, nil
}
