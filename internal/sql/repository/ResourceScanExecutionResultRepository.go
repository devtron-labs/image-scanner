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
	Types                       []int              `sql:"types" pg:",array"`
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
	License         ResourceScanType = 2
	Config          ResourceScanType = 3
	Secrets         ResourceScanType = 4
)

func (t ResourceScanType) ToInt() int {
	return int(t)
}

type ResourceScanResultRepository interface {
	SaveInBatch(models []*ResourceScanResult) error
}

type ResourceScanResultRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewResourceScanResultRepositoryImpl(dbConnection *pg.DB, logger *zap.SugaredLogger) *ResourceScanResultRepositoryImpl {
	return &ResourceScanResultRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}

func (impl ResourceScanResultRepositoryImpl) SaveInBatch(models []*ResourceScanResult) error {
	return impl.dbConnection.Insert(&models)
}
