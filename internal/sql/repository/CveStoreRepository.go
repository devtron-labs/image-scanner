package repository

import (
	"github.com/go-pg/pg"
	"go.uber.org/zap"
)

type CveStore struct {
	tableName    struct{} `sql:"cve_store" pg:",discard_unknown_columns"`
	Name         string   `sql:"name,pk"`
	Severity     Severity `sql:"severity,notnull"`
	Package      string   `sql:"package,notnull"`
	Version      string   `sql:"version,notnull"`
	FixedVersion string   `sql:"fixed_version,notnull"`
	AuditLog
}

type CveStoreRepository interface {
	Save(model *CveStore) error
	FindAll() ([]*CveStore, error)
	FindByCveNames(names []string) ([]*CveStore, error)
	FindByName(name string) (*CveStore, error)
	Update(model *CveStore) error
}

type CveStoreRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewCveStoreRepositoryImpl(dbConnection *pg.DB, logger *zap.SugaredLogger) *CveStoreRepositoryImpl {
	return &CveStoreRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}

func (impl CveStoreRepositoryImpl) Save(model *CveStore) error {
	err := impl.dbConnection.Insert(model)
	return err
}

func (impl CveStoreRepositoryImpl) FindAll() ([]*CveStore, error) {
	var models []*CveStore
	err := impl.dbConnection.Model(&models).Select()
	return models, err
}

func (impl CveStoreRepositoryImpl) FindByCveNames(names []string) ([]*CveStore, error) {
	var models []*CveStore
	err := impl.dbConnection.Model(&models).Where("name in (?)", pg.In(names)).Select()
	return models, err
}

func (impl CveStoreRepositoryImpl) FindByName(name string) (*CveStore, error) {
	var model CveStore
	err := impl.dbConnection.Model(&model).
		Where("name = ?", name).Select()
	return &model, err
}

func (impl CveStoreRepositoryImpl) Update(team *CveStore) error {
	err := impl.dbConnection.Update(team)
	return err
}
