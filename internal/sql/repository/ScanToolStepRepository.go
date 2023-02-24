package repository

import (
	"encoding/json"
	"github.com/devtron-labs/image-scanner/internal/sql/bean"
	cli_util "github.com/devtron-labs/image-scanner/internal/step-lib/util/cli-util"
	"github.com/go-pg/pg"
	"go.uber.org/zap"
)

type ScanToolStep struct {
	tableName         struct{}               `sql:"scan_tool_step" pg:",discard_unknown_columns"`
	Id                int                    `sql:"id,pk"`
	ScanToolId        int                    `sql:"scan_tool_id"`
	Index             int                    `sql:"index"`
	StepExecutionType bean.ScanExecutionType `sql:"step_execution_type"`
	RetryCount        int                    `sql:"retry_count"`          //only applicable if step fails
	ExecuteStepOnFail int                    `sql:"execute_step_on_fail"` //fail means that at least one condition is not matched
	ExecuteStepOnPass int                    `sql:"execute_step_on_pass"` //pass means that all conditions are matched
	InputPayload      json.RawMessage        `sql:"input_payload"`
	HttpReqType       string                 `sql:"http_req_type"`
	HttpReqHeaders    json.RawMessage        `sql:"http_req_headers"`
	HttpQueryParams   json.RawMessage        `sql:"http_query_params"`
	CliFlags          json.RawMessage        `sql:"cli_flags"`
	CliOutputType     cli_util.CliOutputType `sql:"cli_output_type"`
	Deleted           bool                   `sql:"deleted,notnull"`
	ScanToolMetadata
	AuditLog
}

type ScanToolStepRepository interface {
	Save(model *ScanToolStep) (*ScanToolStep, error)
	Update(model *ScanToolStep) (*ScanToolStep, error)
	SaveBulk(model []*ScanToolStep) ([]*ScanToolStep, error)
	UpdateBulk(model []*ScanToolStep) ([]*ScanToolStep, error)
	FindAllByScanToolId(scanToolId int) ([]*ScanToolStep, error)
	MarkDeletedById(id int) error
	MarkAllStepsDeletedByToolId(scanToolId int) error
}

type ScanToolStepRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewScanToolStepRepositoryImpl(dbConnection *pg.DB,
	logger *zap.SugaredLogger) *ScanToolStepRepositoryImpl {
	return &ScanToolStepRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}

func (repo *ScanToolStepRepositoryImpl) Save(model *ScanToolStep) (*ScanToolStep, error) {
	err := repo.dbConnection.Insert(model)
	if err != nil {
		repo.logger.Errorw("error in saving scan tool step", "err", err)
		return nil, err
	}
	return model, nil
}

func (repo *ScanToolStepRepositoryImpl) Update(model *ScanToolStep) (*ScanToolStep, error) {
	err := repo.dbConnection.Update(model)
	if err != nil {
		repo.logger.Errorw("error in updating scan tool step", "err", err)
		return nil, err
	}
	return model, nil
}

func (repo *ScanToolStepRepositoryImpl) SaveBulk(model []*ScanToolStep) ([]*ScanToolStep, error) {
	err := repo.dbConnection.Insert(&model)
	if err != nil {
		repo.logger.Errorw("error in saving scan tool step in bulk", "err", err)
		return nil, err
	}
	return model, nil
}

func (repo *ScanToolStepRepositoryImpl) UpdateBulk(model []*ScanToolStep) ([]*ScanToolStep, error) {
	_, err := repo.dbConnection.Model(&model).Update()
	if err != nil {
		repo.logger.Errorw("error in updating scan tool step in bulk", "err", err)
		return nil, err
	}
	return model, nil
}

func (repo *ScanToolStepRepositoryImpl) FindAllByScanToolId(scanToolId int) ([]*ScanToolStep, error) {
	var model []*ScanToolStep
	err := repo.dbConnection.Model(&model).Where("scan_tool_id = ?", scanToolId).
		Where("deleted = ?", false).Order("index ASC").Select() //ordering by index to get in order of execution
	if err != nil {
		repo.logger.Errorw("error in getting scan tool steps by tool id", "err", err, "scanToolId", scanToolId)
		return nil, err
	}
	return model, nil
}

func (repo *ScanToolStepRepositoryImpl) MarkDeletedById(id int) error {
	model := &ScanToolStep{}
	_, err := repo.dbConnection.Model(model).Set("deleted = ?", true).
		Where("id = ?", id).Update()
	if err != nil {
		repo.logger.Errorw("error in marking step entry deleted by id", "err", err, "id", id)
		return err
	}
	return nil
}

func (repo *ScanToolStepRepositoryImpl) MarkAllStepsDeletedByToolId(scanToolId int) error {
	model := &ScanToolStep{}
	_, err := repo.dbConnection.Model(model).Set("deleted = ?", true).
		Where("scan_tool_id = ?", scanToolId).Update()
	if err != nil {
		repo.logger.Errorw("error in marking steps entry deleted by tool id", "err", err, "scanToolId", scanToolId)
		return err
	}
	return nil
}
