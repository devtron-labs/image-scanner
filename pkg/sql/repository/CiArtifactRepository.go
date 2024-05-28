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
	"time"
)

type CiArtifact struct {
	tableName        struct{}  `sql:"ci_artifact" pg:",discard_unknown_columns"`
	Id               int       `sql:"id,pk"`
	PipelineId       int       `sql:"pipeline_id,notnull"` //id of the ci pipeline from which this webhook was triggered
	Image            string    `sql:"image,notnull"`
	ImageDigest      string    `sql:"image_digest,notnull"`
	MaterialInfo     string    `sql:"material_info"` //git material metadata json array string
	DataSource       string    `sql:"data_source,notnull"`
	WorkflowId       *int      `sql:"ci_workflow_id"`
	ParentCiArtifact int       `sql:"parent_ci_artifact"`
	ScanEnabled      bool      `sql:"scan_enabled"`
	Scanned          bool      `sql:"scanned"`
	DeployedTime     time.Time `sql:"-"`
	Deployed         bool      `sql:"-"`
	Latest           bool      `sql:"-"`
	AuditLog
}

type CiArtifactRepository interface {
	Update(artifact *CiArtifact) error
	Get(imageDigest string) (*CiArtifact, error)
}

type CiArtifactRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewCiArtifactRepositoryImpl(dbConnection *pg.DB, logger *zap.SugaredLogger) *CiArtifactRepositoryImpl {
	return &CiArtifactRepositoryImpl{dbConnection: dbConnection, logger: logger}
}

func (impl CiArtifactRepositoryImpl) Update(artifact *CiArtifact) error {
	return impl.dbConnection.Update(artifact)
}

func (impl CiArtifactRepositoryImpl) Get(imageDigest string) (*CiArtifact, error) {
	var artifact CiArtifact
	//TODO - rethink, is image hash is same for artifact id
	err := impl.dbConnection.Model(&artifact).Where("image_digest = ?", imageDigest).Order("id desc").Limit(1).Select()
	return &artifact, err
}
