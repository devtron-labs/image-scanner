package security

import (
	"context"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/helper"
	"github.com/devtron-labs/image-scanner/internal/sql/bean"
	"github.com/devtron-labs/image-scanner/internal/sql/repository"
	cliUtil "github.com/devtron-labs/image-scanner/internal/step-lib/util/cli-util"
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
	resourceScanResultRepository              repository.ResourceScanResultRepository
	scanToolExecutionHistoryMapping           repository.ScanToolExecutionHistoryMappingRepository
}

func NewCodeScanServiceImpl(logger *zap.SugaredLogger,
	gitManager *helper.GitManager,
	scanToolExecutionHistoryMappingRepository repository.ScanToolExecutionHistoryMappingRepository,
	imageScanDeployInfoRepository repository.ImageScanDeployInfoRepository,
	resourceScanResultRepository repository.ResourceScanResultRepository,
) *CodeScanServiceImpl {
	service := &CodeScanServiceImpl{
		logger: logger,
		scanToolExecutionHistoryMappingRepository: scanToolExecutionHistoryMappingRepository,
		gitManager:                    gitManager,
		imageScanDeployInfoRepository: imageScanDeployInfoRepository,
		resourceScanResultRepository:  resourceScanResultRepository,
	}
	return service
}

func (impl CodeScanServiceImpl) ScanCode(scanEvent *common.ImageScanEvent, tool *repository.ScanToolMetadata, executionHistory *repository.ImageScanExecutionHistory, executionHistoryDirPath string) error {

	var metaId int
	var objectType string
	if scanEvent.SourceSubType == common.SourceSubTypeCi {
		metaId = scanEvent.CiWorkflowId
		objectType = repository.ScanObjectType_CI_Workflow
	} else if scanEvent.SourceSubType == common.SourceSubTypeManifest {
		metaId = scanEvent.CdWorkflowId
		objectType = repository.ScanObjectType_CD_Workflow
	}

	var info *repository.ImageScanDeployInfo
	var err error
	info, err = impl.imageScanDeployInfoRepository.FindByObjectTypeAndId(metaId, objectType)
	if err != nil {
		return err
	}

	if info == nil {
		info = &repository.ImageScanDeployInfo{
			ImageScanExecutionHistoryId: []int{executionHistory.Id},
			ScanObjectMetaId:            metaId,
			ObjectType:                  objectType,
			EnvId:                       1,
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

	path := executionHistoryDirPath + "/code"
	if scanEvent.SourceSubType == common.SourceSubTypeCi {

		err := impl.gitManager.CloneAndCheckout(scanEvent.CiProjectDetails, path)
		if err != nil {
			return err
		}

	} else if scanEvent.SourceSubType == common.SourceSubTypeManifest {
		//TODO
	}
	outputFile := executionHistoryDirPath + "/cicodescan.json"
	renderedCommand := "trivy fs " + path + " --scanners vuln,config,secret,license " + "--license-full " + "--format json " + "-o " + outputFile

	//args := map[string]string{path: "", "--scanners": "vuln,misconfig,secret,license", "--license-full": "", "--format": "json", "-o": outputFile}
	output, err := cliUtil.HandleCliRequest(renderedCommand, outputFile, context.Background(), "STATIC", nil)

	var processedState bean.ScanExecutionProcessState
	var errorMessage string
	if err != nil {
		impl.logger.Errorw("error in processing scan for tool:", tool.Name, "err", err)
		processedState = bean.ScanExecutionProcessStateFailed
		errorMessage = err.Error()
	} else {
		processedState = bean.ScanExecutionProcessStateCompleted
		result := &repository.ResourceScanResult{
			ImageScanExecutionHistoryId: executionHistory.Id,
			ScanDataJson:                string(output),
			Format:                      repository.Json,
			Types:                       []int{repository.Vulnerabilities.ToInt(), repository.License.ToInt(), repository.Secrets.ToInt(), repository.Config.ToInt()},
			ScanToolId:                  tool.Id,
		}
		err := impl.resourceScanResultRepository.SaveInBatch([]*repository.ResourceScanResult{result})
		if err != nil {
			impl.logger.Errorw("error in saving scan result:", "err", err)
			processedState = bean.ScanExecutionProcessStateFailed
		}
	}
	updateErr := impl.scanToolExecutionHistoryMappingRepository.UpdateStateByToolAndExecutionHistoryId(executionHistory.Id, tool.Id, processedState, time.Now(), errorMessage)
	if updateErr != nil {
		impl.logger.Errorw("error in UpdateStateByToolAndExecutionHistoryId", "err", err)
		err = updateErr
	}

	return nil
}
