package repository

import (
	"github.com/devtron-labs/image-scanner/common"
	"github.com/go-pg/pg"
	"go.uber.org/zap"
)

type RegistryIndexMapping struct {
	tableName  struct{}            `sql:"registry_index_mapping" pg:",discard_unknown_columns"`
	Id         int                 `sql:"id,pk"`
	Registry   common.RegistryType `sql:"registry_type"`
	Index      int                 `sql:"starting_index"`
	ScanToolId int                 `sql:"scan_tool_id"`
}

type RegistryIndexMappingRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewRegistryIndexMappingRepositoryImpl(dbConnection *pg.DB,
	logger *zap.SugaredLogger) *RegistryIndexMappingRepositoryImpl {
	return &RegistryIndexMappingRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}

type RegistryIndexMappingRepository interface {
	GetStartingIndexForARegistryAndATool(scanToolid int, registry common.RegistryType) (*RegistryIndexMapping, error)
}

func (repo *RegistryIndexMappingRepositoryImpl) GetStartingIndexForARegistryAndATool(scanToolid int, registry common.RegistryType) (*RegistryIndexMapping, error) {
	var model RegistryIndexMapping
	err := repo.dbConnection.Model(&model).Where("scan_tool_id = ?", scanToolid).Where("registry_type = ?", registry).Select()
	if err != nil {
		return &model, err
	}
	return &model, nil
}
