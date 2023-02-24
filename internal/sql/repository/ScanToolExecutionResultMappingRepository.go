package repository

import (
	"github.com/go-pg/pg"
	"go.uber.org/zap"
)

type ScanToolExecutionResultMapping struct {
	tableName                  struct{} `sql:"scan_tool_execution_result_mapping" pg:",discard_unknown_columns"`
	Id                         int      `sql:"id,pk"`
	ImageScanExecutionResultId int      `sql:"image_scan_execution_result_id"`
	ScanToolId                 int      `sql:"scan_tool_id"`
	ImageScanExecutionResult
	ScanToolMetadata
	AuditLog
}

type ScanToolExecutionResultMappingRepository interface {
}

type ScanToolExecutionResultMappingRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewScanToolExecutionResultMappingRepositoryImpl(dbConnection *pg.DB,
	logger *zap.SugaredLogger) *ScanToolExecutionResultMappingRepositoryImpl {
	return &ScanToolExecutionResultMappingRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}
