package repository

import (
	"github.com/go-pg/pg"
	"go.uber.org/zap"
)

/**
this table contains scanned images registry for deployed object and apps,
images which are deployed on cluster by anyway and has scanned result
*/

// TODO refactor name and column names Subhashish
type ImageScanDeployInfo struct {
	tableName                   struct{} `sql:"image_scan_deploy_info" pg:",discard_unknown_columns"`
	Id                          int      `sql:"id,pk"`
	ImageScanExecutionHistoryId []int    `sql:"image_scan_execution_history_id,notnull" pg:",array"`
	ScanObjectMetaId            int      `sql:"scan_object_meta_id,notnull"`
	ObjectType                  string   `sql:"object_type,notnull"`
	EnvId                       int      `sql:"env_id,notnull"`
	ClusterId                   int      `sql:"cluster_id,notnull"`
	AuditLog
}

const (
	ScanObjectType_APP           string = "app"
	ScanObjectType_CHART         string = "chart"
	ScanObjectType_POD           string = "pod"
	ScanObjectType_CHART_HISTORY string = "chart-history"
	ScanObjectType_CI_Workflow   string = "ci-workflow"
	ScanObjectType_CD_Workflow   string = "cd-workflow"
)

type ImageScanDeployInfoRepository interface {
	Save(model *ImageScanDeployInfo) error
	FindAll() ([]*ImageScanDeployInfo, error)
	FindOne(id int) (*ImageScanDeployInfo, error)
	FindByIds(ids []int) ([]*ImageScanDeployInfo, error)
	Update(model *ImageScanDeployInfo) error
	FetchListingGroupByObject() ([]*ImageScanDeployInfo, error)
	FetchByAppIdAndEnvId(appId int, envId int) (*ImageScanDeployInfo, error)
	FindByObjectTypeAndId(scanObjectMetaId int, objectType string) (*ImageScanDeployInfo, error)
}

type ImageScanDeployInfoRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewImageScanDeployInfoRepositoryImpl(dbConnection *pg.DB, logger *zap.SugaredLogger) *ImageScanDeployInfoRepositoryImpl {
	return &ImageScanDeployInfoRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}

func (impl ImageScanDeployInfoRepositoryImpl) Save(model *ImageScanDeployInfo) error {
	err := impl.dbConnection.Insert(model)
	return err
}

func (impl ImageScanDeployInfoRepositoryImpl) FindAll() ([]*ImageScanDeployInfo, error) {
	var models []*ImageScanDeployInfo
	err := impl.dbConnection.Model(&models).Select()
	return models, err
}

func (impl ImageScanDeployInfoRepositoryImpl) FindOne(id int) (*ImageScanDeployInfo, error) {
	var model ImageScanDeployInfo
	err := impl.dbConnection.Model(&model).
		Where("id = ?", id).Select()
	return &model, err
}

func (impl ImageScanDeployInfoRepositoryImpl) FindByIds(ids []int) ([]*ImageScanDeployInfo, error) {
	var models []*ImageScanDeployInfo
	err := impl.dbConnection.Model(&models).Where("id in (?)", pg.In(ids)).Select()
	return models, err
}

func (impl ImageScanDeployInfoRepositoryImpl) Update(team *ImageScanDeployInfo) error {
	err := impl.dbConnection.Update(team)
	return err
}

func (impl ImageScanDeployInfoRepositoryImpl) FetchListingGroupByObject() ([]*ImageScanDeployInfo, error) {
	var models []*ImageScanDeployInfo
	/*err := impl.dbConnection.Model(&models).
	Column("max(image_scan_deploy_info.id) as id", "image_scan_deploy_info.scan_object_meta_id").
	Group("image_scan_deploy_info.scan_object_meta_id").
	Order("image_scan_deploy_info.id desc").Select()*/
	query := "select scan_object_meta_id,object_type, max(id) as id from image_scan_deploy_info" +
		" group by scan_object_meta_id,object_type order by id desc"
	_, err := impl.dbConnection.Query(&models, query)
	if err != nil {
		impl.logger.Error("err", err)
		return []*ImageScanDeployInfo{}, err
	}
	return models, err
}

func (impl ImageScanDeployInfoRepositoryImpl) FetchByAppIdAndEnvId(appId int, envId int) (*ImageScanDeployInfo, error) {
	var model ImageScanDeployInfo
	err := impl.dbConnection.Model(&model).
		Where("scan_object_meta_id = ?", appId).
		Where("env_id = ?", envId).Where("object_type = ?", "app").
		Order("created_on desc").Limit(1).
		Select()
	return &model, err
}

func (impl ImageScanDeployInfoRepositoryImpl) FindByObjectTypeAndId(scanObjectMetaId int, objectType string) (*ImageScanDeployInfo, error) {
	var model ImageScanDeployInfo
	err := impl.dbConnection.Model(&model).
		Where("scan_object_meta_id = ?", scanObjectMetaId).
		Where("object_type = ?", objectType).
		Order("created_on desc").Limit(1).
		Select()
	if err == pg.ErrNoRows {
		return nil, nil
	}
	return &model, err
}
