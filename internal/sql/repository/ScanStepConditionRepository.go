package repository

import (
	"github.com/go-pg/pg"
	"go.uber.org/zap"
)

type ScanStepCondition struct {
	tableName           struct{} `sql:"scan_step_condition" pg:",discard_unknown_columns"`
	Id                  int      `sql:"id,pk"`
	ConditionalOperator string   `sql:"conditional_operator"`
	ConditionalValue    string   `sql:"conditional_value"`
	ConditionOn         string   `sql:"condition_on"`
	Deleted             bool     `sql:"deleted,notnull"`
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
