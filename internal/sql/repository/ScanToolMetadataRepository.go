package repository

import (
	"github.com/go-pg/pg"
	"go.uber.org/zap"
)

type ScanTargetType string

const (
	ImageScanTargetType ScanTargetType = "IMAGE"
	CodeScanTargetType  ScanTargetType = "CODE"
)

type ScanToolMetadata struct {
	tableName                        struct{}       `sql:"scan_tool_metadata" pg:",discard_unknown_columns"`
	Id                               int            `sql:"id,pk"`
	Name                             string         `sql:"name"`
	Version                          string         `sql:"version"`
	ServerBaseUrl                    string         `sql:"server_base_url"`
	BaseCliCommand                   string         `sql:"base_cli_command"`
	ResultDescriptorTemplateLocation string         `sql:"result_descriptor_template"`
	ScanTarget                       ScanTargetType `sql:"scan_target"`
	Active                           bool           `sql:"active,notnull"`
	Deleted                          bool           `sql:"deleted,notnull"`
	AuditLog
}

type ScanToolMetadataRepository interface {
	FindAllActiveToolsForScanTarget(scanTarget ScanTargetType) ([]*ScanToolMetadata, error)
	FindActiveById(id int) (*ScanToolMetadata, error)
	Save(model *ScanToolMetadata) (*ScanToolMetadata, error)
	Update(model *ScanToolMetadata) (*ScanToolMetadata, error)
	MarkToolDeletedById(id int) error
}

type ScanToolMetadataRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewScanToolMetadataRepositoryImpl(dbConnection *pg.DB,
	logger *zap.SugaredLogger) *ScanToolMetadataRepositoryImpl {
	return &ScanToolMetadataRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}

func (repo *ScanToolMetadataRepositoryImpl) FindAllActiveToolsForScanTarget(scanTargetType ScanTargetType) ([]*ScanToolMetadata, error) {
	models := make([]*ScanToolMetadata, 0)
	err := repo.dbConnection.Model(&models).Where("active = ?", true).
		Where("scan_target = ?", scanTargetType).
		Where("deleted = ?", false).Select()
	if err != nil {
		repo.logger.Errorw("error in getting all active tools for scan target", "err", err, "scanTargetType", scanTargetType)
		return nil, err
	}
	return models, nil
}

func (repo *ScanToolMetadataRepositoryImpl) FindActiveById(id int) (*ScanToolMetadata, error) {
	model := &ScanToolMetadata{}
	err := repo.dbConnection.Model(model).Where("id = ?", id).
		Where("active = ?", true).
		Where("deleted = ?", false).Select()
	if err != nil {
		repo.logger.Errorw("error in getting active by id", "err", err, "id", id)
		return nil, err
	}
	return model, nil
}

func (repo *ScanToolMetadataRepositoryImpl) Save(model *ScanToolMetadata) (*ScanToolMetadata, error) {
	err := repo.dbConnection.Insert(model)
	if err != nil {
		repo.logger.Errorw("error in saving scan tool metadata", "err", err, "model", model)
		return nil, err
	}
	return model, nil
}

func (repo *ScanToolMetadataRepositoryImpl) Update(model *ScanToolMetadata) (*ScanToolMetadata, error) {
	err := repo.dbConnection.Update(model)
	if err != nil {
		repo.logger.Errorw("error in updating scan tool metadata", "err", err, "model", model)
		return nil, err
	}
	return model, nil
}

func (repo *ScanToolMetadataRepositoryImpl) MarkToolDeletedById(id int) error {
	model := &ScanToolMetadata{}
	_, err := repo.dbConnection.Model(model).Set("deleted = ?", true).
		Where("id = ?", id).Update()
	if err != nil {
		repo.logger.Errorw("error in marking tool entry deleted by id", "err", err, "id", id)
		return err
	}
	return nil
}
