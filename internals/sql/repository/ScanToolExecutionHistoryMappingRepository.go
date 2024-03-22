package repository

import (
	"github.com/devtron-labs/image-scanner/internals/sql/bean"
	"github.com/go-pg/pg"
	"go.uber.org/zap"
	"time"
)

type ScanToolExecutionHistoryMapping struct {
	tableName                   struct{}                       `sql:"scan_tool_execution_history_mapping" pg:",discard_unknown_columns"`
	Id                          int                            `sql:"id,pk"`
	ImageScanExecutionHistoryId int                            `sql:"image_scan_execution_history_id"`
	ScanToolId                  int                            `sql:"scan_tool_id"`
	ExecutionStartTime          time.Time                      `sql:"execution_start_time,notnull"`
	ExecutionFinishTime         time.Time                      `sql:"execution_finish_time,notnull"`
	State                       bean.ScanExecutionProcessState `sql:"state"`
	TryCount                    int                            `sql:"try_count"`
	AuditLog
}

type ScanToolExecutionHistoryMappingRepository interface {
	Save(model *ScanToolExecutionHistoryMapping) error
	SaveInBatch(models []*ScanToolExecutionHistoryMapping) error
	UpdateStateByToolAndExecutionHistoryId(executionHistoryId, toolId int, state bean.ScanExecutionProcessState, executionFinishTime time.Time) error
	MarkAllRunningStateAsFailedHavingTryCountReachedLimit(tryCount int) error
	GetAllScanHistoriesByState(state bean.ScanExecutionProcessState) ([]*ScanToolExecutionHistoryMapping, error)
	GetAllScanHistoriesByExecutionHistoryIdAndStates(executionHistoryId int, states []bean.ScanExecutionProcessState) ([]*ScanToolExecutionHistoryMapping, error)
}

type ScanToolExecutionHistoryMappingRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewScanToolExecutionHistoryMappingRepositoryImpl(dbConnection *pg.DB,
	logger *zap.SugaredLogger) *ScanToolExecutionHistoryMappingRepositoryImpl {
	return &ScanToolExecutionHistoryMappingRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}

func (repo *ScanToolExecutionHistoryMappingRepositoryImpl) Save(model *ScanToolExecutionHistoryMapping) error {
	err := repo.dbConnection.Insert(model)
	if err != nil {
		repo.logger.Errorw("error in ScanToolExecutionHistoryMappingRepository, Save", "model", model, "err", err)
		return err
	}
	return nil
}

func (repo *ScanToolExecutionHistoryMappingRepositoryImpl) SaveInBatch(models []*ScanToolExecutionHistoryMapping) error {
	err := repo.dbConnection.Insert(&models)
	if err != nil {
		repo.logger.Errorw("error in ScanToolExecutionHistoryMappingRepository, SaveInBatch", "err", err, "models", models)
		return err
	}
	return nil
}

func (repo *ScanToolExecutionHistoryMappingRepositoryImpl) UpdateStateByToolAndExecutionHistoryId(executionHistoryId, toolId int,
	state bean.ScanExecutionProcessState, executionFinishTime time.Time) error {
	model := &ScanToolExecutionHistoryMapping{}
	_, err := repo.dbConnection.Model(model).Set("state = ?", state).
		Set("execution_finish_time  = ?", executionFinishTime).
		Where("image_scan_execution_history_id = ?", executionHistoryId).
		Where("scan_tool_id = ?", toolId).Update()
	if err != nil {
		repo.logger.Errorw("error in ScanToolExecutionHistoryMappingRepository, SaveInBatch", "err", err, "model", model)
		return err
	}
	return nil
}

func (repo *ScanToolExecutionHistoryMappingRepositoryImpl) MarkAllRunningStateAsFailedHavingTryCountReachedLimit(tryCount int) error {
	var models []*ScanToolExecutionHistoryMapping
	_, err := repo.dbConnection.Model(&models).
		Set("state = ?", bean.ScanExecutionProcessStateFailed).
		Where("state = ?", bean.ScanExecutionProcessStateRunning).
		Where("try_count > ?", tryCount).Update()
	if err != nil {
		repo.logger.Errorw("error in ScanToolExecutionHistoryMappingRepository, MarkAllRunningStateAsFailedHavingTryCountReachedLimit", "err", err)
		return err
	}
	return nil
}

func (repo *ScanToolExecutionHistoryMappingRepositoryImpl) GetAllScanHistoriesByState(state bean.ScanExecutionProcessState) ([]*ScanToolExecutionHistoryMapping, error) {
	var models []*ScanToolExecutionHistoryMapping
	err := repo.dbConnection.Model(&models).Column("scan_tool_execution_history_mapping.*").
		Where("state = ?", state).Select()
	if err != nil {
		repo.logger.Errorw("error in ScanToolExecutionHistoryMappingRepository, GetAllScanHistoriesByState", "err", err)
		return nil, err
	}
	return models, nil
}

func (repo *ScanToolExecutionHistoryMappingRepositoryImpl) GetAllScanHistoriesByExecutionHistoryIdAndStates(executionHistoryId int, states []bean.ScanExecutionProcessState) ([]*ScanToolExecutionHistoryMapping, error) {
	var models []*ScanToolExecutionHistoryMapping
	err := repo.dbConnection.Model(&models).Column("scan_tool_execution_history_mapping.*").
		Where("image_scan_execution_history_id = ?", executionHistoryId).
		Where("state in (?)", pg.In(states)).Select()
	if err != nil {
		repo.logger.Errorw("error in ScanToolExecutionHistoryMappingRepository, GetAllScanHistoriesByState", "err", err)
		return nil, err
	}
	return models, nil
}
