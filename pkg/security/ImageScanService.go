package security

import (
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/internal/sql/repository"
	"github.com/go-pg/pg"
	"github.com/optiopay/klar/clair"
	"go.uber.org/zap"
	"time"
)

type ImageScanService interface {
	CreateScanExecutionRegistry(vs []*clair.Vulnerability, event *common.ScanEvent) ([]*clair.Vulnerability, error)
	IsImageScanned(image string) (bool, error)
}

type ImageScanServiceImpl struct {
	Logger                        *zap.SugaredLogger
	scanHistoryRepository         repository.ImageScanHistoryRepository
	scanResultRepository          repository.ImageScanResultRepository
	scanObjectMetaRepository      repository.ImageScanObjectMetaRepository
	cveStoreRepository            repository.CveStoreRepository
	imageScanDeployInfoRepository repository.ImageScanDeployInfoRepository
	ciArtifactRepository          repository.CiArtifactRepository
}

func NewImageScanServiceImpl(Logger *zap.SugaredLogger, scanHistoryRepository repository.ImageScanHistoryRepository,
	scanResultRepository repository.ImageScanResultRepository, scanObjectMetaRepository repository.ImageScanObjectMetaRepository,
	cveStoreRepository repository.CveStoreRepository, imageScanDeployInfoRepository repository.ImageScanDeployInfoRepository,
	ciArtifactRepository repository.CiArtifactRepository) *ImageScanServiceImpl {
	return &ImageScanServiceImpl{Logger: Logger, scanHistoryRepository: scanHistoryRepository, scanResultRepository: scanResultRepository,
		scanObjectMetaRepository: scanObjectMetaRepository, cveStoreRepository: cveStoreRepository,
		imageScanDeployInfoRepository: imageScanDeployInfoRepository,
		ciArtifactRepository:          ciArtifactRepository,
	}
}

func (impl *ImageScanServiceImpl) CreateScanExecutionRegistry(vs []*clair.Vulnerability, event *common.ScanEvent) ([]*clair.Vulnerability, error) {

	var cveNames []string
	for _, item := range vs {
		impl.Logger.Debugw("vulnerability data", "vs", item)
		cveStore, err := impl.cveStoreRepository.FindByName(item.Name)
		if err != nil && err != pg.ErrNoRows {
			impl.Logger.Errorw("Failed to fetch cve", "err", err)
			return nil, err
		}
		if len(cveStore.Name) == 0 {
			cveStore = &repository.CveStore{
				Name:         item.Name,
				Package:      item.FeatureName,
				Version:      item.FeatureVersion,
				FixedVersion: item.FixedBy,
			}
			if item.Severity == "High" {
				cveStore.Severity = 2
			} else if item.Severity == "Medium" {
				cveStore.Severity = 1
			} else if item.Severity == "Low" {
				cveStore.Severity = 0
			}
			cveStore.CreatedOn = time.Now()
			cveStore.CreatedBy = int32(event.UserId)
			cveStore.UpdatedOn = time.Now()
			cveStore.UpdatedBy = int32(event.UserId)
			err := impl.cveStoreRepository.Save(cveStore)
			if err != nil {
				impl.Logger.Errorw("Failed to save cve", "err", err)
				return nil, err
			}
			cveNames = append(cveNames, cveStore.Name)
		} else {
			cveNames = append(cveNames, cveStore.Name)
		}
	}
	imageScanExecutionHistory := &repository.ImageScanExecutionHistory{
		Image:         event.Image,
		ImageHash:     event.ImageDigest,
		ExecutionTime: time.Now(),
		ExecutedBy:    event.UserId,
	}
	err := impl.scanHistoryRepository.Save(imageScanExecutionHistory)
	if err != nil {
		impl.Logger.Errorw("Failed to save cve", "err", err)
		return nil, err
	}
	for _, cveName := range cveNames {
		imageScanExecutionResult := &repository.ImageScanExecutionResult{
			ImageScanExecutionHistoryId: imageScanExecutionHistory.Id,
			CveStoreName:                cveName,
		}
		err := impl.scanResultRepository.Save(imageScanExecutionResult)
		if err != nil {
			impl.Logger.Errorw("Failed to save cve", "err", err)
			return nil, err
		}
	}

	/*	ciArtifact, err := impl.ciArtifactRepository.Get(event.ImageDigest)
		if err != nil {
			impl.Logger.Errorw("Failed to get artifact", "err", err)
			return nil, err
		}
		ciArtifact.Scanned = true
		ciArtifact.UpdatedOn = time.Now()
		ciArtifact.UpdatedBy = int32(event.UserId)
		err = impl.ciArtifactRepository.Update(ciArtifact)
		if err != nil {
			impl.Logger.Errorw("Failed to update artifact", "err", err)
			return nil, err
		}*/
	return vs, nil
}

func (impl *ImageScanServiceImpl) IsImageScanned(image string) (bool, error) {
	scanned := false
	scanHistory, err := impl.scanHistoryRepository.FindByImage(image)
	if err != nil && err != pg.ErrNoRows {
		impl.Logger.Errorw("error in fetching scan history ", "err", err)
		return scanned, err
	}
	if scanHistory != nil && scanHistory.Id > 0 {
		scanned = true
	}
	return scanned, err
}
