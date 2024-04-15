//go:build wireinject
// +build wireinject

package main

import (
	"github.com/devtron-labs/common-lib/monitoring"
	client "github.com/devtron-labs/common-lib/pubsub-lib"
	"github.com/devtron-labs/image-scanner/api"
	"github.com/devtron-labs/image-scanner/helper"
	"github.com/devtron-labs/image-scanner/internal/logger"
	"github.com/devtron-labs/image-scanner/internal/sql"
	"github.com/devtron-labs/image-scanner/internal/sql/repository"
	"github.com/devtron-labs/image-scanner/pkg/clairService"
	"github.com/devtron-labs/image-scanner/pkg/grafeasService"
	"github.com/devtron-labs/image-scanner/pkg/klarService"
	"github.com/devtron-labs/image-scanner/pkg/security"
	"github.com/devtron-labs/image-scanner/pkg/user"
	"github.com/devtron-labs/image-scanner/pubsub"
	"github.com/google/wire"
)

func InitializeApp() (*App, error) {
	wire.Build(
		NewApp,
		api.NewRouter,
		logger.NewSugardLogger,
		logger.NewHttpClient,
		sql.GetConfig,
		sql.NewDbConnection,
		api.NewRestHandlerImpl,
		wire.Bind(new(api.RestHandler), new(*api.RestHandlerImpl)),
		klarService.GetKlarConfig,
		grafeasService.GetGrafeasClient,
		client.NewPubSubClientServiceImpl,
		klarService.NewKlarServiceImpl,
		wire.Bind(new(klarService.KlarService), new(*klarService.KlarServiceImpl)),
		pubsub.NewNatSubscription,
		grafeasService.NewKlarServiceImpl,
		wire.Bind(new(grafeasService.GrafeasService), new(*grafeasService.GrafeasServiceImpl)),
		//pubsub.NewTestPublishImpl,
		//wire.Bind(new(pubsub.TestPublish), new(*pubsub.TestPublishImpl)),

		clairService.GetClairConfig,
		clairService.NewClairServiceImpl,
		wire.Bind(new(clairService.ClairService), new(*clairService.ClairServiceImpl)),

		user.NewUserServiceImpl,
		wire.Bind(new(user.UserService), new(*user.UserServiceImpl)),
		repository.NewUserRepositoryImpl,
		wire.Bind(new(repository.UserRepository), new(*repository.UserRepositoryImpl)),
		security.GetImageScannerConfig,
		security.NewImageScanServiceImpl,
		wire.Bind(new(security.ImageScanService), new(*security.ImageScanServiceImpl)),
		repository.NewImageScanHistoryRepositoryImpl,
		wire.Bind(new(repository.ImageScanHistoryRepository), new(*repository.ImageScanHistoryRepositoryImpl)),
		repository.NewImageScanResultRepositoryImpl,
		wire.Bind(new(repository.ImageScanResultRepository), new(*repository.ImageScanResultRepositoryImpl)),
		repository.NewImageScanObjectMetaRepositoryImpl,
		wire.Bind(new(repository.ImageScanObjectMetaRepository), new(*repository.ImageScanObjectMetaRepositoryImpl)),
		repository.NewCveStoreRepositoryImpl,
		wire.Bind(new(repository.CveStoreRepository), new(*repository.CveStoreRepositoryImpl)),
		repository.NewImageScanDeployInfoRepositoryImpl,
		wire.Bind(new(repository.ImageScanDeployInfoRepository), new(*repository.ImageScanDeployInfoRepositoryImpl)),
		repository.NewCiArtifactRepositoryImpl,
		wire.Bind(new(repository.CiArtifactRepository), new(*repository.CiArtifactRepositoryImpl)),
		repository.NewDockerArtifactStoreRepositoryImpl,
		wire.Bind(new(repository.DockerArtifactStoreRepository), new(*repository.DockerArtifactStoreRepositoryImpl)),
		repository.NewRegistryIndexMappingRepositoryImpl,
		wire.Bind(new(repository.RegistryIndexMappingRepository), new(*repository.RegistryIndexMappingRepositoryImpl)),

		repository.NewScanToolMetadataRepositoryImpl,
		wire.Bind(new(repository.ScanToolMetadataRepository), new(*repository.ScanToolMetadataRepositoryImpl)),
		repository.NewScanToolStepRepositoryImpl,
		wire.Bind(new(repository.ScanToolStepRepository), new(*repository.ScanToolStepRepositoryImpl)),
		repository.NewScanStepConditionRepositoryImpl,
		wire.Bind(new(repository.ScanStepConditionRepository), new(*repository.ScanStepConditionRepositoryImpl)),
		repository.NewScanStepConditionMappingRepositoryImpl,
		wire.Bind(new(repository.ScanStepConditionMappingRepository), new(*repository.ScanStepConditionMappingRepositoryImpl)),

		repository.NewScanToolExecutionHistoryMappingRepositoryImpl,
		wire.Bind(new(repository.ScanToolExecutionHistoryMappingRepository), new(*repository.ScanToolExecutionHistoryMappingRepositoryImpl)),
		monitoring.NewMonitoringRouter,
		helper.NewGitManagerImpl,
		helper.NewGitCliManager,
		wire.Bind(new(helper.GitCliManager), new(*helper.GitCliManagerImpl)),

		security.NewCodeScanServiceImpl,
		wire.Bind(new(security.CodeScanService), new(*security.CodeScanServiceImpl)),
	)
	return &App{}, nil
}
