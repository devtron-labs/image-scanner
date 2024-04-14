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
	Type                        ResourceScanType   `sql:"type"`
}

type ResourceScanFormat int

const (
	CycloneDx ResourceScanFormat = 1 //SBOM
	TrivyJson                    = 2
	Json                         = 3
)

//const CycloneDx ResourceScanFormat = 1

type ResourceScanType int

const (
	LicenseVulnerabilities   ResourceScanType = 1
	SecretsMisconfigurations                  = 2
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
