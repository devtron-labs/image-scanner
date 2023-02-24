package repository

import (
	"github.com/go-pg/pg"
	"go.uber.org/zap"
)

type ScanStepConditionMapping struct {
	tableName                  struct{} `sql:"scan_step_condition_mapping" pg:",discard_unknown_columns"`
	Id                         int      `sql:"id,pk"`
	ScanStepConditionId        int      `sql:"scan_step_condition_id"`
	ScanStepConditionMappingId int      `sql:"scan_tool_step_id"`
	ScanToolMetadata
	ScanStepCondition
	AuditLog
}

type ScanStepConditionMappingRepository interface {
	Save(model *ScanStepConditionMapping) (*ScanStepConditionMapping, error)
	Update(model *ScanStepConditionMapping) (*ScanStepConditionMapping, error)
	SaveBulk(model []*ScanStepConditionMapping) ([]*ScanStepConditionMapping, error)
	UpdateBulk(model []*ScanStepConditionMapping) ([]*ScanStepConditionMapping, error)
}

type ScanStepConditionMappingRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewScanStepConditionMappingRepositoryImpl(dbConnection *pg.DB,
	logger *zap.SugaredLogger) *ScanStepConditionMappingRepositoryImpl {
	return &ScanStepConditionMappingRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}

func (repo *ScanStepConditionMappingRepositoryImpl) Save(model *ScanStepConditionMapping) (*ScanStepConditionMapping, error) {
	err := repo.dbConnection.Insert(model)
	if err != nil {
		repo.logger.Errorw("error in saving scan step condition mapping", "err", err)
		return nil, err
	}
	return model, nil
}

func (repo *ScanStepConditionMappingRepositoryImpl) Update(model *ScanStepConditionMapping) (*ScanStepConditionMapping, error) {
	err := repo.dbConnection.Update(model)
	if err != nil {
		repo.logger.Errorw("error in updating scan step condition mapping", "err", err)
		return nil, err
	}
	return model, nil
}

func (repo *ScanStepConditionMappingRepositoryImpl) SaveBulk(model []*ScanStepConditionMapping) ([]*ScanStepConditionMapping, error) {
	err := repo.dbConnection.Insert(&model)
	if err != nil {
		repo.logger.Errorw("error in saving scan step condition mapping in bulk", "err", err)
		return nil, err
	}
	return model, nil
}

func (repo *ScanStepConditionMappingRepositoryImpl) UpdateBulk(model []*ScanStepConditionMapping) ([]*ScanStepConditionMapping, error) {
	_, err := repo.dbConnection.Model(&model).Update()
	if err != nil {
		repo.logger.Errorw("error in updating scan step condition mapping in bulk", "err", err)
		return nil, err
	}
	return model, nil
}
