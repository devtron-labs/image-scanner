package security

import (
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/helper"
	"github.com/devtron-labs/image-scanner/internal/sql/repository"
	"go.uber.org/zap"
)

type CodeScanService interface {
	ScanCode(scanEvent *common.ImageScanEvent, tool *repository.ScanToolMetadata, executionHistory *repository.ImageScanExecutionHistory, executionHistoryDirPath string) error
}

type CodeScanServiceImpl struct {
	logger                                    *zap.SugaredLogger
	gitManager                                *helper.GitManager
	scanToolExecutionHistoryMappingRepository repository.ScanToolExecutionHistoryMappingRepository
}

func NewCodeScanServiceImpl(logger *zap.SugaredLogger,
	gitManager *helper.GitManager,
	scanToolExecutionHistoryMappingRepository repository.ScanToolExecutionHistoryMappingRepository,
) *CodeScanServiceImpl {
	service := &CodeScanServiceImpl{
		logger: logger,
		scanToolExecutionHistoryMappingRepository: scanToolExecutionHistoryMappingRepository,
		gitManager: gitManager,
	}
	return service
}

func (impl CodeScanServiceImpl) ScanCode(scanEvent *common.ImageScanEvent, tool *repository.ScanToolMetadata, executionHistory *repository.ImageScanExecutionHistory, executionHistoryDirPath string) error {

	if scanEvent.SourceSubType == common.SourceSubTypeCi {

		err := impl.gitManager.CloneAndCheckout(scanEvent.CiProjectDetails, executionHistoryDirPath+"/code")
		if err != nil {
			return err
		}

		//updateErr := impl.scanToolExecutionHistoryMappingRepository.UpdateStateByToolAndExecutionHistoryId(executionHistoryId, toolCopy.Id, processedState, time.Now(), errorMessage)
		//if updateErr != nil {
		//	impl.logger.Errorw("error in UpdateStateByToolAndExecutionHistoryId", "err", err)
		//	err = updateErr
		//}

	} else if scanEvent.SourceSubType == common.SourceSubTypeManifest {

	}
	return nil
}
