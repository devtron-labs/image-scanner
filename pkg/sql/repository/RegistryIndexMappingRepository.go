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
)

type RegistryIndexMapping struct {
	tableName  struct{}            `sql:"registry_index_mapping" pg:",discard_unknown_columns"`
	Id         int                 `sql:"id,pk"`
	Registry   common.RegistryType `sql:"registry_type"`
	Index      int                 `sql:"starting_index"`
	ScanToolId int                 `sql:"scan_tool_id"`
}

type RegistryIndexMappingRepositoryImpl struct {
	DbConnection *pg.DB
	Logger       *zap.SugaredLogger
}

func NewRegistryIndexMappingRepositoryImpl(dbConnection *pg.DB,
	logger *zap.SugaredLogger) *RegistryIndexMappingRepositoryImpl {
	return &RegistryIndexMappingRepositoryImpl{
		DbConnection: dbConnection,
		Logger:       logger,
	}
}

type RegistryIndexMappingRepository interface {
	GetStartingIndexForARegistryAndATool(scanToolid int, registry common.RegistryType) (*RegistryIndexMapping, error)
}

func (repo *RegistryIndexMappingRepositoryImpl) GetStartingIndexForARegistryAndATool(scanToolid int, registry common.RegistryType) (*RegistryIndexMapping, error) {
	var model RegistryIndexMapping
	err := repo.DbConnection.Model(&model).Where("scan_tool_id = ?", scanToolid).Where("registry_type = ?", registry).Select()
	if err != nil {
		return &model, err
	}
	return &model, nil
}
