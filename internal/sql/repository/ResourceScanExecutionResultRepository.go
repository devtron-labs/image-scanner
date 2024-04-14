package repository

import (
	"github.com/go-pg/pg"
	"go.uber.org/zap"
)

type ResourceScanResult struct {
	tableName                   struct{}           `sql:"resource_scan_execution_result" pg:",discard_unknown_columns"`
	Id                          int                `sql:"id,pk"`
	ImageScanExecutionHistoryId int                `sql:"image_scan_execution_history_id"`
	ScanDataJson                string             `sql:"scan_data_json"`
	Format                      ResourceScanFormat `sql:"format"`
	Types                       []ResourceScanType `sql:"types"`
	ScanToolId                  int                `sql:"scan_tool_id"`
}

type ResourceScanFormat int

const (
	CycloneDxSbom ResourceScanFormat = 1 //SBOM
	TrivyJson                        = 2
	Json                             = 3
)

type ResourceScanType int

const (
	Vulnerabilities ResourceScanType = 1
	License                          = 2
	Config                           = 3
	Secrets                          = 4
)

type ResourceScanResultRepository interface {
	SaveInBatch(tx *pg.Tx, models []*ResourceScanResult) error
}

type ResourceScanResultRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewResourceScanResultRepositoryImpl(dbConnection *pg.DB, logger *zap.SugaredLogger) *ImageScanResultRepositoryImpl {
	return &ImageScanResultRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}

func (impl ResourceScanResultRepositoryImpl) SaveInBatch(tx *pg.Tx, models []*ResourceScanResult) error {
	return tx.Insert(&models)
}
