package security

import (
	"context"
	"fmt"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/helper"
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

	path := executionHistoryDirPath + "/code"
	if scanEvent.SourceSubType == common.SourceSubTypeCi {

		err := impl.gitManager.CloneAndCheckout(scanEvent.CiProjectDetails, path)
		if err != nil {
			return err
		}

	} else if scanEvent.SourceSubType == common.SourceSubTypeManifest {
		//TODO
	}

	renderedCommand := "trivy fs"
	outputFile := "cicodescan.json"
	args := map[string]string{path: "", "--scanners": "vuln,misconfig,secret,license", "--license-full": "", "--format": "json", "-o": outputFile}
	output, err := cliUtil.HandleCliRequest(renderedCommand, outputFile, context.Background(), "STATIC", args)
	fmt.Println(output)

	return nil
}
