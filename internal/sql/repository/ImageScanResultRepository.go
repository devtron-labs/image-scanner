package repository

import (
	"github.com/go-pg/pg"
	"go.uber.org/zap"
)

type ImageScanExecutionResult struct {
	tableName                   struct{} `sql:"image_scan_execution_result" pg:",discard_unknown_columns"`
	Id                          int      `sql:"id,pk"`
	CveStoreName                string   `sql:"cve_store_name,notnull"`
	ImageScanExecutionHistoryId int      `sql:"image_scan_execution_history_id"` //TODO: remove this
	ScanToolId                  int      `sql:"scan_tool_id"`
	CveStore                    CveStore
	ImageScanExecutionHistory   ImageScanExecutionHistory
}

type ImageScanResultRepository interface {
	Save(model *ImageScanExecutionResult) error
	SaveInBatch(models []*ImageScanExecutionResult, tx *pg.Tx) error
	FindAll() ([]*ImageScanExecutionResult, error)
	FindOne(id int) (*ImageScanExecutionResult, error)
	FindByCveName(name string) ([]*ImageScanExecutionResult, error)
	Update(model *ImageScanExecutionResult) error
	FetchByScanExecutionId(id int) ([]*ImageScanExecutionResult, error)
	FetchByScanExecutionIds(ids []int) ([]*ImageScanExecutionResult, error)
}

type ImageScanResultRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewImageScanResultRepositoryImpl(dbConnection *pg.DB, logger *zap.SugaredLogger) *ImageScanResultRepositoryImpl {
	return &ImageScanResultRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}

func (impl ImageScanResultRepositoryImpl) Save(model *ImageScanExecutionResult) error {
	err := impl.dbConnection.Insert(model)
	return err
}

func (impl ImageScanResultRepositoryImpl) SaveInBatch(models []*ImageScanExecutionResult, tx *pg.Tx) error {
	err := tx.Insert(&models)
	return err
}

func (impl ImageScanResultRepositoryImpl) FindAll() ([]*ImageScanExecutionResult, error) {
	var models []*ImageScanExecutionResult
	err := impl.dbConnection.Model(&models).Select()
	return models, err
}

func (impl ImageScanResultRepositoryImpl) FindOne(id int) (*ImageScanExecutionResult, error) {
	var model *ImageScanExecutionResult
	err := impl.dbConnection.Model(&model).
		Where("id = ?", id).Select()
	return model, err
}

func (impl ImageScanResultRepositoryImpl) FindByCveName(name string) ([]*ImageScanExecutionResult, error) {
	var model []*ImageScanExecutionResult
	err := impl.dbConnection.Model(&model).
		Where("cve_store_name = ?", name).Select()
	return model, err
}

func (impl ImageScanResultRepositoryImpl) Update(team *ImageScanExecutionResult) error {
	err := impl.dbConnection.Update(team)
	return err
}

func (impl ImageScanResultRepositoryImpl) FetchByScanExecutionId(scanExecutionId int) ([]*ImageScanExecutionResult, error) {
	var models []*ImageScanExecutionResult
	err := impl.dbConnection.Model(&models).Column("image_scan_execution_result.*", "CveStore").
		Where("image_scan_execution_result.image_scan_execution_history_id = ?", scanExecutionId).
		Select()
	return models, err
}

func (impl ImageScanResultRepositoryImpl) FetchByScanExecutionIds(ids []int) ([]*ImageScanExecutionResult, error) {
	var models []*ImageScanExecutionResult
	err := impl.dbConnection.Model(&models).Column("image_scan_execution_result.*", "ImageScanExecutionHistory", "CveStore").
		Where("image_scan_execution_result.image_scan_execution_history_id in(?)", pg.In(ids)).
		Select()
	return models, err
}
