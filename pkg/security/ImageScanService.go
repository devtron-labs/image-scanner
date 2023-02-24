package security

import (
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/internal/sql/repository"
	thread_lib "github.com/devtron-labs/image-scanner/internal/thread-lib"
	"github.com/go-pg/pg"
	"github.com/optiopay/klar/clair"
	"github.com/quay/claircore"
	"go.uber.org/zap"
	"sync"
	"time"
)

type ImageScanService interface {
	CreateScanExecutionRegistryForClairV4(vs []*claircore.Vulnerability, event *common.ImageScanEvent) ([]*claircore.Vulnerability, error)
	CreateScanExecutionRegistryForClairV2(vs []*clair.Vulnerability, event *common.ImageScanEvent) ([]*clair.Vulnerability, error)
	IsImageScanned(image string) (bool, error)
}

type ImageScanServiceImpl struct {
	logger                                   *zap.SugaredLogger
	scanHistoryRepository                    repository.ImageScanHistoryRepository
	scanResultRepository                     repository.ImageScanResultRepository
	scanObjectMetaRepository                 repository.ImageScanObjectMetaRepository
	cveStoreRepository                       repository.CveStoreRepository
	imageScanDeployInfoRepository            repository.ImageScanDeployInfoRepository
	ciArtifactRepository                     repository.CiArtifactRepository
	scanToolExecutionResultMappingRepository repository.ScanToolExecutionResultMappingRepository
	scanToolMetadataRepository               repository.ScanToolMetadataRepository
	scanStepConditionRepository              repository.ScanStepConditionRepository
	scanToolStepRepository                   repository.ScanToolStepRepository
	scanStepConditionMappingRepository       repository.ScanStepConditionMappingRepository
	threadPool                               thread_lib.ThreadPool
}

func NewImageScanServiceImpl(logger *zap.SugaredLogger, scanHistoryRepository repository.ImageScanHistoryRepository,
	scanResultRepository repository.ImageScanResultRepository, scanObjectMetaRepository repository.ImageScanObjectMetaRepository,
	cveStoreRepository repository.CveStoreRepository, imageScanDeployInfoRepository repository.ImageScanDeployInfoRepository,
	ciArtifactRepository repository.CiArtifactRepository,
	scanToolExecutionResultMappingRepository repository.ScanToolExecutionResultMappingRepository,
	scanToolMetadataRepository repository.ScanToolMetadataRepository,
	scanStepConditionRepository repository.ScanStepConditionRepository,
	scanToolStepRepository repository.ScanToolStepRepository,
	scanStepConditionMappingRepository repository.ScanStepConditionMappingRepository,
	threadPool thread_lib.ThreadPool) *ImageScanServiceImpl {
	return &ImageScanServiceImpl{logger: logger, scanHistoryRepository: scanHistoryRepository, scanResultRepository: scanResultRepository,
		scanObjectMetaRepository: scanObjectMetaRepository, cveStoreRepository: cveStoreRepository,
		imageScanDeployInfoRepository:            imageScanDeployInfoRepository,
		ciArtifactRepository:                     ciArtifactRepository,
		scanToolExecutionResultMappingRepository: scanToolExecutionResultMappingRepository,
		scanToolMetadataRepository:               scanToolMetadataRepository,
		scanStepConditionRepository:              scanStepConditionRepository,
		scanToolStepRepository:                   scanToolStepRepository,
		scanStepConditionMappingRepository:       scanStepConditionMappingRepository,
		threadPool:                               threadPool,
	}
}

func (impl *ImageScanServiceImpl) ScanImage(scanEvent *common.ImageScanEvent) error {
	//checking if image is already scanned or not
	isImageScanned, err := impl.IsImageScanned(scanEvent.Image)
	if err != nil && err != pg.ErrNoRows {
		impl.logger.Errorw("error in fetching scan history ", "err", err, "image", scanEvent.Image)
		return err
	}
	if isImageScanned {
		impl.logger.Infow("image already scanned, skipping further process", "image", scanEvent.Image)
		return nil
	}
	//get all active tools
	tools, err := impl.scanToolMetadataRepository.FindAllActiveToolsForScanTarget(repository.ImageScanTargetType)
	if err != nil {
		impl.logger.Errorw("error in getting all active tools", "")
		return err
	}
	//TODO: maintain state of execution from db
	toolsForWhichProcessingFailed := make([]string, 0)
	toolsForWhichProcessingSucceeded := make([]string, 0)
	mutex := &sync.Mutex{}
	wg := &sync.WaitGroup{}
	wg.Add(len(tools))
	for _, tool := range tools {
		toolCopy := *tool
		impl.threadPool.AddThreadToExecutionQueue(func() {
			err = impl.ProcessScanForATool(toolCopy)
			if err != nil {
				impl.logger.Errorw("error in processing scan for tool:", toolCopy.Name, "err", err)
				mutex.Lock()
				toolsForWhichProcessingFailed = append(toolsForWhichProcessingFailed)
				mutex.Unlock()
				//TODO: update failed status for this tool immediately
			} else {
				mutex.Lock()
				toolsForWhichProcessingSucceeded = append(toolsForWhichProcessingSucceeded)
				mutex.Unlock()
			}
			wg.Done()
		})
	}
	wg.Wait()
	return nil
}

func (impl *ImageScanServiceImpl) ProcessScanForATool(tool repository.ScanToolMetadata) error {

	//getting all steps for this tool
	steps, err := impl.scanToolStepRepository.FindAllByScanToolId(tool.Id)
	if err != nil {
		impl.logger.Errorw("error in getting steps by scan tool id", "err", err, "toolId", tool.Id)
		return err
	}
	wg := &sync.WaitGroup{}
	wg.Add(len(steps))
	for _, step := range steps {
		stepCopy := *step
		go func() {
			err = impl.ProcessScanStep(stepCopy)
			if err != nil {
				impl.logger.Errorw("error in processing scan step", "err", err, "stepId", stepCopy.Id)
			}
			wg.Done()
		}()
	}
	wg.Wait()
	return nil
}

func (impl *ImageScanServiceImpl) ProcessScanStep(step repository.ScanToolStep) error {
	return nil
}

func (impl *ImageScanServiceImpl) CreateScanExecutionRegistryForClairV4(vulnerabilities []*claircore.Vulnerability, event *common.ImageScanEvent) ([]*claircore.Vulnerability, error) {

	var cveNames []string
	for _, item := range vulnerabilities {
		impl.logger.Debugw("vulnerability data", "vs", item)
		cveStore, err := impl.cveStoreRepository.FindByName(item.Name)
		if err != nil && err != pg.ErrNoRows {
			impl.logger.Errorw("Failed to fetch cve", "err", err)
			return nil, err
		}
		if len(cveStore.Name) == 0 {
			cveStore = &repository.CveStore{
				Name:         item.Name,
				Package:      item.Package.Name,
				Version:      item.Package.Version,
				FixedVersion: item.FixedInVersion,
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
				impl.logger.Errorw("Failed to save cve", "err", err)
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
		impl.logger.Errorw("Failed to save cve", "err", err)
		return nil, err
	}
	for _, cveName := range cveNames {
		imageScanExecutionResult := &repository.ImageScanExecutionResult{
			ImageScanExecutionHistoryId: imageScanExecutionHistory.Id,
			CveStoreName:                cveName,
		}
		err := impl.scanResultRepository.Save(imageScanExecutionResult)
		if err != nil {
			impl.logger.Errorw("Failed to save cve", "err", err)
			return nil, err
		}
	}
	return vulnerabilities, nil
}

func (impl *ImageScanServiceImpl) CreateScanExecutionRegistryForClairV2(vs []*clair.Vulnerability, event *common.ImageScanEvent) ([]*clair.Vulnerability, error) {

	var cveNames []string
	for _, item := range vs {
		impl.logger.Debugw("vulnerability data", "vs", item)
		cveStore, err := impl.cveStoreRepository.FindByName(item.Name)
		if err != nil && err != pg.ErrNoRows {
			impl.logger.Errorw("Failed to fetch cve", "err", err)
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
				impl.logger.Errorw("Failed to save cve", "err", err)
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
		impl.logger.Errorw("Failed to save cve", "err", err)
		return nil, err
	}
	for _, cveName := range cveNames {
		imageScanExecutionResult := &repository.ImageScanExecutionResult{
			ImageScanExecutionHistoryId: imageScanExecutionHistory.Id,
			CveStoreName:                cveName,
		}
		err := impl.scanResultRepository.Save(imageScanExecutionResult)
		if err != nil {
			impl.logger.Errorw("Failed to save cve", "err", err)
			return nil, err
		}
	}
	return vs, nil
}

func (impl *ImageScanServiceImpl) IsImageScanned(image string) (bool, error) {
	scanned := false
	scanHistory, err := impl.scanHistoryRepository.FindByImage(image)
	if err != nil && err != pg.ErrNoRows {
		impl.logger.Errorw("error in fetching scan history ", "err", err)
		return scanned, err
	}
	if scanHistory != nil && scanHistory.Id > 0 {
		scanned = true
	}
	return scanned, err
}
