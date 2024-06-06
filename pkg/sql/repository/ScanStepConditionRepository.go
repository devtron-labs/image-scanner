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
)

type ScanStepCondition struct {
	tableName               struct{}            `sql:"scan_step_condition" pg:",discard_unknown_columns"`
	Id                      int                 `sql:"id,pk"`
	ConditionVariableFormat bean.VariableFormat `sql:"condition_variable_format"`
	ConditionalOperator     string              `sql:"conditional_operator"`
	ConditionalValue        string              `sql:"conditional_value"`
	ConditionOn             string              `sql:"condition_on"` //json path of variable on which condition is to be applied
	Deleted                 bool                `sql:"deleted,notnull"`
	AuditLog
}

type ScanStepConditionRepository interface {
	Save(model *ScanStepCondition) (*ScanStepCondition, error)
	Update(model *ScanStepCondition) (*ScanStepCondition, error)
	SaveBulk(model []*ScanStepCondition) ([]*ScanStepCondition, error)
	UpdateBulk(model []*ScanStepCondition) ([]*ScanStepCondition, error)
	FindAllByToolStepId(toolStepId int) ([]*ScanStepCondition, error)
	MarkDeletedById(id int) error
	MarkAllConditionsDeletedByToolStepId(toolStepId int) error
}

type ScanStepConditionRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewScanStepConditionRepositoryImpl(dbConnection *pg.DB,
	logger *zap.SugaredLogger) *ScanStepConditionRepositoryImpl {
	return &ScanStepConditionRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}

func (repo *ScanStepConditionRepositoryImpl) Save(model *ScanStepCondition) (*ScanStepCondition, error) {
	err := repo.dbConnection.Insert(model)
	if err != nil {
		repo.logger.Errorw("error in saving scan step condition ", "err", err)
		return nil, err
	}
	return model, nil
}

func (repo *ScanStepConditionRepositoryImpl) Update(model *ScanStepCondition) (*ScanStepCondition, error) {
	err := repo.dbConnection.Update(model)
	if err != nil {
		repo.logger.Errorw("error in updating scan step condition ", "err", err)
		return nil, err
	}
	return model, nil
}

func (repo *ScanStepConditionRepositoryImpl) SaveBulk(model []*ScanStepCondition) ([]*ScanStepCondition, error) {
	err := repo.dbConnection.Insert(&model)
	if err != nil {
		repo.logger.Errorw("error in saving scan step condition  in bulk", "err", err)
		return nil, err
	}
	return model, nil
}

func (repo *ScanStepConditionRepositoryImpl) UpdateBulk(model []*ScanStepCondition) ([]*ScanStepCondition, error) {
	_, err := repo.dbConnection.Model(&model).Update()
	if err != nil {
		repo.logger.Errorw("error in updating scan step condition  in bulk", "err", err)
		return nil, err
	}
	return model, nil
}

func (repo *ScanStepConditionRepositoryImpl) FindAllByToolStepId(toolStepId int) ([]*ScanStepCondition, error) {
	var model []*ScanStepCondition
	err := repo.dbConnection.Model(&model).
		Join("LEFT JOIN scan_step_condition_mapping sscp ON scan_step_condition.id=sscp.scan_step_condition_id").
		Where("sscp.scan_tool_step_id = ?", toolStepId).
		Where("scan_step_condition.deleted = ?", false).Select()
	if err != nil {
		repo.logger.Errorw("error in getting scan step conditions by step id", "err", err, "toolStepId", toolStepId)
		return nil, err
	}
	return model, nil
}

func (repo *ScanStepConditionRepositoryImpl) MarkDeletedById(id int) error {
	model := &ScanStepCondition{}
	_, err := repo.dbConnection.Model(model).Set("deleted = ?", true).
		Where("id = ?", id).Update()
	if err != nil {
		repo.logger.Errorw("error in marking condition deleted by id", "err", err, "id", id)
		return err
	}
	return nil
}

func (repo *ScanStepConditionRepositoryImpl) MarkAllConditionsDeletedByToolStepId(toolStepId int) error {
	model := &ScanStepCondition{}
	_, err := repo.dbConnection.Model(model).Set("deleted = ?", true).
		Join("LEFT JOIN scan_step_condition_mapping sscp ON scan_step_condition.id=sscp.scan_step_condition_id").
		Where("sscp.scan_tool_step_id = ?", toolStepId).Update()
	if err != nil {
		repo.logger.Errorw("error in marking conditions deleted by tool step id", "err", err, "toolStepid", toolStepId)
		return err
	}
	return nil
}
