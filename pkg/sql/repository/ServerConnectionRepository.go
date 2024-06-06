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
	"github.com/devtron-labs/common-lib/utils/remoteConnection/bean"
	"github.com/go-pg/pg"
	"go.uber.org/zap"
)

type RemoteConnectionRepository interface {
	GetById(id int) (*RemoteConnectionConfig, error)
}

type RemoteConnectionRepositoryImpl struct {
	logger       *zap.SugaredLogger
	dbConnection *pg.DB
}

func NewRemoteConnectionRepositoryImpl(dbConnection *pg.DB, logger *zap.SugaredLogger) *RemoteConnectionRepositoryImpl {
	return &RemoteConnectionRepositoryImpl{
		logger:       logger,
		dbConnection: dbConnection,
	}
}

type RemoteConnectionConfig struct {
	tableName        struct{}                    `sql:"remote_connection_config" pg:",discard_unknown_columns"`
	Id               int                         `sql:"id,pk"`
	ConnectionMethod bean.RemoteConnectionMethod `sql:"connection_method"`
	ProxyUrl         string                      `sql:"proxy_url"`
	SSHServerAddress string                      `sql:"ssh_server_address"`
	SSHUsername      string                      `sql:"ssh_username"`
	SSHPassword      string                      `sql:"ssh_password"`
	SSHAuthKey       string                      `sql:"ssh_auth_key"`
	Deleted          bool                        `sql:"deleted,notnull"`
	AuditLog
}

func (repo *RemoteConnectionRepositoryImpl) GetById(id int) (*RemoteConnectionConfig, error) {
	model := &RemoteConnectionConfig{}
	err := repo.dbConnection.Model(model).
		Where("id = ?", id).
		Where("deleted = ?", false).
		Select()
	if err != nil && err != pg.ErrNoRows {
		repo.logger.Errorw("error in getting server connection config", "err", err, "id", id)
		return nil, err
	}
	return model, nil
}
