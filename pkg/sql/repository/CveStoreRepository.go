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
	"github.com/devtron-labs/image-scanner/pkg/sql/bean"
	"github.com/go-pg/pg"
	"go.uber.org/zap"
	"time"
)

type CveStore struct {
	tableName        struct{}      `sql:"cve_store" pg:",discard_unknown_columns"`
	Name             string        `sql:"name,pk"`
	Severity         bean.Severity `sql:"severity,notnull"`
	Package          string        `sql:"package,notnull"` // deprecated, storing package data in image_scan_execution_result table
	Version          string        `sql:"version,notnull"`
	FixedVersion     string        `sql:"fixed_version,notnull"`
	StandardSeverity bean.Severity `sql:"standard_severity,notnull"`
	AuditLog
}

func (cve *CveStore) CreateAuditLog(userId int32) {
	cve.CreatedBy = userId
	cve.CreatedOn = time.Now()
	cve.UpdatedBy = userId
	cve.UpdatedOn = time.Now()
}

func (cve *CveStore) UpdateNewSeverityInCveStore(severity bean.Severity, standardSeverity bean.Severity, userId int32) {
	cve.Severity = severity
	cve.StandardSeverity = standardSeverity
	cve.UpdatedOn = time.Now()
	cve.UpdatedBy = userId
}

type CveStoreRepository interface {
	GetConnection() (dbConnection *pg.DB)
	Save(model *CveStore) error
	SaveInBatch(model []*CveStore, tx *pg.Tx) error
	FindAll() ([]*CveStore, error)
	FindByCveNames(names []string) ([]*CveStore, error)
	FindByName(name string) (*CveStore, error)
	Update(model *CveStore) error
	UpdateInBatch(model []*CveStore, tx *pg.Tx) ([]*CveStore, error)
}

type CveStoreRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewCveStoreRepositoryImpl(dbConnection *pg.DB, logger *zap.SugaredLogger) *CveStoreRepositoryImpl {
	return &CveStoreRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}

func (impl CveStoreRepositoryImpl) GetConnection() (dbConnection *pg.DB) {
	return impl.dbConnection
}

func (impl CveStoreRepositoryImpl) Save(model *CveStore) error {
	err := impl.dbConnection.Insert(model)
	return err
}

func (impl CveStoreRepositoryImpl) SaveInBatch(model []*CveStore, tx *pg.Tx) error {
	err := tx.Insert(&model)
	return err
}
func (impl CveStoreRepositoryImpl) FindAll() ([]*CveStore, error) {
	var models []*CveStore
	err := impl.dbConnection.Model(&models).Select()
	return models, err
}

func (impl CveStoreRepositoryImpl) FindByCveNames(names []string) ([]*CveStore, error) {
	var models []*CveStore
	err := impl.dbConnection.Model(&models).Where("name in (?)", pg.In(names)).Select()
	return models, err
}

func (impl CveStoreRepositoryImpl) FindByName(name string) (*CveStore, error) {
	var model CveStore
	err := impl.dbConnection.Model(&model).
		Where("name = ?", name).Select()
	return &model, err
}

func (impl CveStoreRepositoryImpl) Update(team *CveStore) error {
	err := impl.dbConnection.Update(team)
	return err
}

// UpdateInBatch updates the cve store model in bulk in db, returns the updated models
func (impl CveStoreRepositoryImpl) UpdateInBatch(models []*CveStore, tx *pg.Tx) ([]*CveStore, error) {
	_, err := impl.dbConnection.Model(&models).Update()
	if err != nil {
		impl.logger.Errorw("error in UpdateInBatch CveStore", "err", err)
		return nil, err
	}
	return models, nil
}
