package security

import (
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/helper"
	"github.com/devtron-labs/image-scanner/internal/sql/repository"
	"go.uber.org/zap"
	"time"
)

type CodeScanService interface {
	ScanCode(scanEvent *common.ImageScanEvent, tool *repository.ScanToolMetadata, executionHistory *repository.ImageScanExecutionHistory, executionHistoryDirPath string) error
}

type CodeScanServiceImpl struct {
	logger                                    *zap.SugaredLogger
	gitManager                                *helper.GitManager
	scanToolExecutionHistoryMappingRepository repository.ScanToolExecutionHistoryMappingRepository
	imageScanDeployInfoRepository             repository.ImageScanDeployInfoRepository
}

func NewCodeScanServiceImpl(logger *zap.SugaredLogger,
	gitManager *helper.GitManager,
	scanToolExecutionHistoryMappingRepository repository.ScanToolExecutionHistoryMappingRepository,
	imageScanDeployInfoRepository repository.ImageScanDeployInfoRepository,
) *CodeScanServiceImpl {
	service := &CodeScanServiceImpl{
		logger: logger,
		scanToolExecutionHistoryMappingRepository: scanToolExecutionHistoryMappingRepository,
		gitManager:                    gitManager,
		imageScanDeployInfoRepository: imageScanDeployInfoRepository,
	}
	return service
}

func (impl CodeScanServiceImpl) ScanCode(scanEvent *common.ImageScanEvent, tool *repository.ScanToolMetadata, executionHistory *repository.ImageScanExecutionHistory, executionHistoryDirPath string) error {

	var info *repository.ImageScanDeployInfo
	var err error
	info, err = impl.imageScanDeployInfoRepository.FindByObjectTypeAndId(scanEvent.CiWorkflowId, repository.ScanObjectType_CI_Workflow)
	if err != nil {
		return err
	}

	if info == nil {
		info = &repository.ImageScanDeployInfo{
			ImageScanExecutionHistoryId: []int{executionHistory.Id},
			ScanObjectMetaId:            scanEvent.CiWorkflowId,
			ObjectType:                  repository.ScanObjectType_CI_Workflow,
			EnvId:                       scanEvent.EnvId,
			ClusterId:                   1,
			AuditLog: repository.AuditLog{
				CreatedOn: time.Now(),
				CreatedBy: 1,
				UpdatedOn: time.Now(),
				UpdatedBy: 1,
			},
		}
		err := impl.imageScanDeployInfoRepository.Save(info)
		if err != nil {
			return err
		}

	} else {
		info.ImageScanExecutionHistoryId = append(info.ImageScanExecutionHistoryId, executionHistory.Id)
		info.UpdatedOn = time.Now()
		err := impl.imageScanDeployInfoRepository.Update(info)
		if err != nil {
			return err
		}
	}

	//requestJson, _ := json.Marshal(scanRequest)
	//historyCode := &security2.ImageScanExecutionHistory{
	//	ExecutionTime:      time.Now(),
	//	ExecutedBy:         bean4.SYSTEM_USER_ID,
	//	SourceMetadataJson: string(requestJson),
	//	SourceType:         security2.SourceTypeCode,
	//	SourceSubType:      security2.SourceSubTypeCi,
	//}
	//err = impl.imageScanHistoryRepo.Save(historyCode)
	//if err != nil {
	//	impl.logger.Error("Error on saving ImageScanExecutionHistory", "error", err, "history", historyCode)
	//	return
	//}
	//scanRequest.ScanHistoryId = historyCode.Id

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
