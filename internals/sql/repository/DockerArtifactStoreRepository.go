package repository

import (
	"github.com/devtron-labs/common-lib/utils/serverConnection/bean"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/go-pg/pg"
	"go.uber.org/zap"
	"net/url"
)

const (
	REGISTRYTYPE_ECR              = "ecr"
	REGISTRYTYPE_OTHER            = "other"
	REGISTRYTYPE_DOCKER_HUB       = "docker-hub"
	REGISTRYTYPE_GCR              = "gcr"
	REGISTRYTYPE_ARTIFACTREGISTRY = "artifact-registry"
)

type DockerArtifactStore struct {
	tableName              struct{}            `sql:"docker_artifact_store" json:",omitempty"  pg:",discard_unknown_columns"`
	Id                     string              `sql:"id,pk" json:"id,,omitempty"`
	PluginId               string              `sql:"plugin_id,notnull" json:"pluginId,omitempty"`
	RegistryURL            string              `sql:"registry_url" json:"registryUrl,omitempty"`
	RegistryType           common.RegistryType `sql:"registry_type,notnull" json:"registryType,omitempty"`
	AWSAccessKeyId         string              `sql:"aws_accesskey_id" json:"awsAccessKeyId,omitempty" `
	AWSSecretAccessKey     string              `sql:"aws_secret_accesskey" json:"awsSecretAccessKey,omitempty"`
	AWSRegion              string              `sql:"aws_region" json:"awsRegion,omitempty"`
	Username               string              `sql:"username" json:"username,omitempty"`
	Password               string              `sql:"password" json:"password,omitempty"`
	IsDefault              bool                `sql:"is_default,notnull" json:"isDefault"`
	Connection             string              `sql:"connection" json:"connection,omitempty"`
	Cert                   string              `sql:"cert" json:"cert,omitempty"`
	Active                 bool                `sql:"active,notnull" json:"active"`
	ServerConnectionConfig *bean.ServerConnectionConfigBean
	AuditLog
}

func (store *DockerArtifactStore) GetRegistryLocation() (registryLocation string, err error) {
	u, err := url.Parse(registryLocation)
	if err != nil {
		return "", err
	} else {
		return u.Host, nil
	}
}

type DockerArtifactStoreRepository interface {
	FindActiveDefaultStore() (*DockerArtifactStore, error)
	FindById(id string) (*DockerArtifactStore, error)
}

type DockerArtifactStoreRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewDockerArtifactStoreRepositoryImpl(dbConnection *pg.DB,
	logger *zap.SugaredLogger) *DockerArtifactStoreRepositoryImpl {
	return &DockerArtifactStoreRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}

func (impl DockerArtifactStoreRepositoryImpl) FindActiveDefaultStore() (*DockerArtifactStore, error) {
	store := &DockerArtifactStore{}
	err := impl.dbConnection.Model(store).
		Where("is_default = ?", true).
		Where("active = ?", true).Select()
	if err != nil {
		impl.logger.Errorw("error in finding default docker registry details", "err", err)
	}
	return store, err
}

func (impl DockerArtifactStoreRepositoryImpl) FindById(id string) (*DockerArtifactStore, error) {
	var provider DockerArtifactStore
	err := impl.dbConnection.Model(&provider).
		Column("docker_artifact_store.*", "ServerConnectionConfig").
		Where("id = ?", id).
		Where("active = ?", true).
		Select()
	if err != nil {
		impl.logger.Errorw("error in finding docker store details by id", "err", err, "id", id)
	}
	return &provider, err
}
