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
	"github.com/devtron-labs/image-scanner/common"
	"github.com/go-pg/pg"
	"go.uber.org/zap"
	"time"
)

type ImageScanExecutionHistory struct {
	tableName                     struct{}             `sql:"image_scan_execution_history" pg:",discard_unknown_columns"`
	Id                            int                  `sql:"id,pk"`
	Image                         string               `sql:"image,notnull"`
	ImageHash                     string               `sql:"image_hash,notnull"` // TODO Migrate to request metadata
	ExecutionTime                 time.Time            `sql:"execution_time"`
	ExecutedBy                    int                  `sql:"executed_by,notnull"`
	SourceMetadataJson            string               `sql:"source_metadata_json"`             // to have relevant info to process a scan for a given source type and subtype
	ExecutionHistoryDirectoryPath string               `sql:"execution_history_directory_path"` // Deprecated
	SourceType                    common.SourceType    `sql:"source_type"`
	SourceSubType                 common.SourceSubType `sql:"source_sub_type"`
}

type ImageScanHistoryRepository interface {
	GetConnection() (dbConnection *pg.DB)
	Save(tx *pg.Tx, model *ImageScanExecutionHistory) error
	FindAll() ([]*ImageScanExecutionHistory, error)
	FindOne(id int) (*ImageScanExecutionHistory, error)
	FindByImageDigest(image string) (*ImageScanExecutionHistory, error)
	FindByImageDigests(digest []string) ([]*ImageScanExecutionHistory, error)
	Update(model *ImageScanExecutionHistory) error
	FindByImage(image string) (*ImageScanExecutionHistory, error)
}

type ImageScanHistoryRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewImageScanHistoryRepositoryImpl(dbConnection *pg.DB, logger *zap.SugaredLogger) *ImageScanHistoryRepositoryImpl {
	return &ImageScanHistoryRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}

func (impl ImageScanHistoryRepositoryImpl) GetConnection() (dbConnection *pg.DB) {
	return impl.dbConnection
}

func (impl ImageScanHistoryRepositoryImpl) Save(tx *pg.Tx, model *ImageScanExecutionHistory) error {
	err := tx.Insert(model)
	return err
}

func (impl ImageScanHistoryRepositoryImpl) FindAll() ([]*ImageScanExecutionHistory, error) {
	var models []*ImageScanExecutionHistory
	err := impl.dbConnection.Model(&models).Select()
	return models, err
}

func (impl ImageScanHistoryRepositoryImpl) FindOne(id int) (*ImageScanExecutionHistory, error) {
	var model ImageScanExecutionHistory
	err := impl.dbConnection.Model(&model).
		Where("id = ?", id).Select()
	return &model, err
}

func (impl ImageScanHistoryRepositoryImpl) FindByImageDigest(image string) (*ImageScanExecutionHistory, error) {
	var model ImageScanExecutionHistory
	err := impl.dbConnection.Model(&model).
		Where("image_hash = ?", image).Order("execution_time desc").Limit(1).Select()
	return &model, err
}

func (impl ImageScanHistoryRepositoryImpl) FindByImageDigests(digest []string) ([]*ImageScanExecutionHistory, error) {
	var models []*ImageScanExecutionHistory
	err := impl.dbConnection.Model(&models).
		Where("image_hash in (?)", pg.In(digest)).Order("execution_time desc").Select()
	return models, err
}

func (impl ImageScanHistoryRepositoryImpl) Update(team *ImageScanExecutionHistory) error {
	err := impl.dbConnection.Update(team)
	return err
}

func (impl ImageScanHistoryRepositoryImpl) FindByImage(image string) (*ImageScanExecutionHistory, error) {
	var model ImageScanExecutionHistory
	err := impl.dbConnection.Model(&model).
		Where("image = ?", image).Order("execution_time desc").Limit(1).Select()
	return &model, err
}
