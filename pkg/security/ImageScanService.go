package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Knetic/govaluate"
	"github.com/caarlos0/env"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/internal/sql/bean"
	"github.com/devtron-labs/image-scanner/internal/sql/repository"
	cliUtil "github.com/devtron-labs/image-scanner/internal/step-lib/util/cli-util"
	commonUtil "github.com/devtron-labs/image-scanner/internal/step-lib/util/common-util"
	httpUtil "github.com/devtron-labs/image-scanner/internal/step-lib/util/http-util"
	"github.com/go-pg/pg"
	"github.com/optiopay/klar/clair"
	"github.com/quay/claircore"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
	"net/url"
	"os"
	"path"
	"strconv"
	"sync"
	"text/template"
	"time"
)

type ImageScanService interface {
	ScanImage(scanEvent *common.ImageScanEvent, tool *repository.ScanToolMetadata, executionHistory *repository.ImageScanExecutionHistory, executionHistoryDirPath string) error
	CreateScanExecutionRegistryForClairV4(vs []*claircore.Vulnerability, event *common.ImageScanEvent, toolId int, executionHistory *repository.ImageScanExecutionHistory) ([]*claircore.Vulnerability, error)
	CreateScanExecutionRegistryForClairV2(vs []*clair.Vulnerability, event *common.ImageScanEvent, toolId int, executionHistory *repository.ImageScanExecutionHistory) ([]*clair.Vulnerability, error)
	IsImageScanned(image string) (bool, error)
	GetActiveTool() (*repository.ScanToolMetadata, error)
	RegisterScanExecutionHistoryAndState(scanEvent *common.ImageScanEvent, tool *repository.ScanToolMetadata) (*repository.ImageScanExecutionHistory, string, error)
}

type ImageScanServiceImpl struct {
	logger                                    *zap.SugaredLogger
	scanHistoryRepository                     repository.ImageScanHistoryRepository
	scanResultRepository                      repository.ImageScanResultRepository
	scanObjectMetaRepository                  repository.ImageScanObjectMetaRepository
	cveStoreRepository                        repository.CveStoreRepository
	imageScanDeployInfoRepository             repository.ImageScanDeployInfoRepository
	ciArtifactRepository                      repository.CiArtifactRepository
	scanToolExecutionHistoryMappingRepository repository.ScanToolExecutionHistoryMappingRepository
	scanToolMetadataRepository                repository.ScanToolMetadataRepository
	scanStepConditionRepository               repository.ScanStepConditionRepository
	scanToolStepRepository                    repository.ScanToolStepRepository
	scanStepConditionMappingRepository        repository.ScanStepConditionMappingRepository
	imageScanConfig                           *ImageScanConfig
	dockerArtifactStoreRepository             repository.DockerArtifactStoreRepository
	registryIndexMappingRepository            repository.RegistryIndexMappingRepository
	codeScanService                           CodeScanService
	resourceScanResultRepository              repository.ResourceScanResultRepository
}

func NewImageScanServiceImpl(logger *zap.SugaredLogger, scanHistoryRepository repository.ImageScanHistoryRepository,
	scanResultRepository repository.ImageScanResultRepository, scanObjectMetaRepository repository.ImageScanObjectMetaRepository,
	cveStoreRepository repository.CveStoreRepository, imageScanDeployInfoRepository repository.ImageScanDeployInfoRepository,
	ciArtifactRepository repository.CiArtifactRepository,
	scanToolExecutionHistoryMappingRepository repository.ScanToolExecutionHistoryMappingRepository,
	scanToolMetadataRepository repository.ScanToolMetadataRepository,
	scanStepConditionRepository repository.ScanStepConditionRepository,
	scanToolStepRepository repository.ScanToolStepRepository,
	scanStepConditionMappingRepository repository.ScanStepConditionMappingRepository,
	imageScanConfig *ImageScanConfig,
	dockerArtifactStoreRepository repository.DockerArtifactStoreRepository, registryIndexMappingRepository repository.RegistryIndexMappingRepository,
	codeScanService CodeScanService,
	resourceScanResultRepository repository.ResourceScanResultRepository,
) *ImageScanServiceImpl {
	imageScanService := &ImageScanServiceImpl{logger: logger, scanHistoryRepository: scanHistoryRepository, scanResultRepository: scanResultRepository,
		scanObjectMetaRepository: scanObjectMetaRepository, cveStoreRepository: cveStoreRepository,
		imageScanDeployInfoRepository:             imageScanDeployInfoRepository,
		ciArtifactRepository:                      ciArtifactRepository,
		scanToolExecutionHistoryMappingRepository: scanToolExecutionHistoryMappingRepository,
		scanToolMetadataRepository:                scanToolMetadataRepository,
		scanStepConditionRepository:               scanStepConditionRepository,
		scanToolStepRepository:                    scanToolStepRepository,
		scanStepConditionMappingRepository:        scanStepConditionMappingRepository,
		imageScanConfig:                           imageScanConfig,
		dockerArtifactStoreRepository:             dockerArtifactStoreRepository,
		registryIndexMappingRepository:            registryIndexMappingRepository,
		codeScanService:                           codeScanService,
		resourceScanResultRepository:              resourceScanResultRepository,
	}
	imageScanService.handleProgressingScans()
	return imageScanService
}

func (impl *ImageScanServiceImpl) GetActiveTool() (*repository.ScanToolMetadata, error) {
	//get active tool
	tool, err := impl.scanToolMetadataRepository.FindActiveToolByScanTarget(repository.ImageScanTargetType)
	if err != nil {
		impl.logger.Errorw("error in getting active tool by scan target", "err", err, "scanTarget", repository.ImageScanTargetType)
		return nil, err
	}
	return tool, nil
}
func (impl *ImageScanServiceImpl) ScanImage(scanEvent *common.ImageScanEvent, tool *repository.ScanToolMetadata, executionHistory *repository.ImageScanExecutionHistory, executionHistoryDirPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(impl.imageScanConfig.ScanImageTimeout)*time.Minute)
	defer cancel()
	//checking if image is already scanned or not
	isImageScanned, err := impl.IsImageScanned(scanEvent.Image)
	if err != nil && err != pg.ErrNoRows {
		impl.logger.Errorw("error in fetching scan history ", "err", err, "image", scanEvent.Image)
		return err
	}
	//TODO handle for rescans for new history Id
	if isImageScanned {
		impl.logger.Infow("image already scanned, skipping further process", "image", scanEvent.Image)
		return nil
	}
	imageScanRenderDto, err := impl.getImageScanRenderDto(scanEvent.DockerRegistryId, scanEvent.Image)
	if err != nil {
		impl.logger.Errorw("service error, getImageScanRenderDto", "err", err, "dockerRegistryId", scanEvent.DockerRegistryId)
		return err
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	// TODO: if multiple processes are to be done in parallel, then error propagation should have to be done via channels

	isV2 := false
	if scanEvent.SourceType == common.SourceTypeImage {
		isV2 = true
	}
	output, err := impl.scanImageForTool(tool, executionHistory.Id, executionHistoryDirPath, wg, int32(scanEvent.UserId), ctx, imageScanRenderDto, isV2)
	if isV2 {
		err = impl.processImageScanSbom(scanEvent, tool, executionHistory.Id, output)
		if err != nil {
			impl.logger.Errorw("err in processImageScanSbom", "err", err)
		}
	}
	if err != nil {
		impl.logger.Errorw("err in scanning image", "err", err, "tool", tool, "executionHistory.Id", executionHistory.Id, "executionHistoryDirPath", executionHistoryDirPath, "scanEvent.UserId", scanEvent.UserId)
		return err
	}

	wg.Wait()
	return err
}

func (impl *ImageScanServiceImpl) getImageScanRenderDto(registryId string, image string) (*common.ImageScanRenderDto, error) {

	dockerRegistry, err := impl.dockerArtifactStoreRepository.FindById(registryId)
	if err == pg.ErrNoRows {
		dockerRegistry = &repository.DockerArtifactStore{}
	} else if err != nil {
		impl.logger.Errorw("error in getting docker registry by id", "err", err, "id", registryId)
		return nil, err
	}
	imageScanRenderDto := &common.ImageScanRenderDto{
		RegistryType:       dockerRegistry.RegistryType,
		Username:           dockerRegistry.Username,
		Password:           dockerRegistry.Password,
		AWSAccessKeyId:     dockerRegistry.AWSAccessKeyId,
		AWSSecretAccessKey: dockerRegistry.AWSSecretAccessKey,
		AWSRegion:          dockerRegistry.AWSRegion,
		Image:              image,
	}
	return imageScanRenderDto, nil
}

func (impl *ImageScanServiceImpl) scanImageForTool(tool *repository.ScanToolMetadata, executionHistoryId int,
	executionHistoryDirPathCopy string, wg *sync.WaitGroup, userId int32, ctx context.Context, imageScanRenderDto *common.ImageScanRenderDto, isV2 bool) (string, error) {
	toolCopy := *tool
	var processedState bean.ScanExecutionProcessState
	output, err := impl.ProcessScanForTool(toolCopy, executionHistoryDirPathCopy, executionHistoryId, userId, ctx, imageScanRenderDto, isV2)
	var errorMessage string
	if err != nil {
		impl.logger.Errorw("error in processing scan for tool:", toolCopy.Name, "err", err)
		processedState = bean.ScanExecutionProcessStateFailed
		errorMessage = err.Error()
	} else {
		processedState = bean.ScanExecutionProcessStateCompleted
	}

	updateErr := impl.scanToolExecutionHistoryMappingRepository.UpdateStateByToolAndExecutionHistoryId(executionHistoryId, toolCopy.Id, processedState, time.Now(), errorMessage)
	if updateErr != nil {
		impl.logger.Errorw("error in UpdateStateByToolAndExecutionHistoryId", "err", err)
		err = updateErr
	}
	wg.Done()
	return output, err
}
func (impl *ImageScanServiceImpl) createFolderForOutputData(executionHistoryModelId int) string {
	executionHistoryModelIdStr := strconv.Itoa(executionHistoryModelId)
	executionHistoryDirPath := path.Join(bean.ScanOutputDirectory, executionHistoryModelIdStr)
	return executionHistoryDirPath
}

func (impl *ImageScanServiceImpl) RegisterScanExecutionHistoryAndState(scanEvent *common.ImageScanEvent,
	tool *repository.ScanToolMetadata) (*repository.ImageScanExecutionHistory, string, error) {
	executionHistoryDirPath := ""
	//creating execution history
	executionTimeStart := time.Now()
	scanEventJson, err := json.Marshal(scanEvent)
	if err != nil {
		impl.logger.Errorw("error in marshalling scanEvent", "err", err, "event", scanEvent)
		return nil, "", err
	}
	executionHistoryModel := &repository.ImageScanExecutionHistory{
		Image:              scanEvent.Image,
		ImageHash:          scanEvent.ImageDigest,
		ExecutionTime:      executionTimeStart,
		ExecutedBy:         scanEvent.UserId,
		SourceMetadataJson: string(scanEventJson),
		SourceType:         scanEvent.SourceType,
		SourceSubType:      scanEvent.SourceSubType,
	}

	err = impl.scanHistoryRepository.Save(executionHistoryModel)
	if err != nil {
		impl.logger.Errorw("Failed to save executionHistory", "err", err, "model", executionHistoryModel)
		return nil, executionHistoryDirPath, err
	}

	// creating folder for storing all details if not exist
	isExist, err := DoesFileExist(bean.ScanOutputDirectory)
	if err != nil {
		impl.logger.Errorw("error in checking if scan output directory exist ", "err", err)
		return nil, executionHistoryDirPath, err
	}
	if !isExist {
		err = os.Mkdir(bean.ScanOutputDirectory, commonUtil.DefaultFileCreatePermission)
		if err != nil && !os.IsExist(err) {
			impl.logger.Errorw("error in creating Output directory", "err", err, "toolId", tool.Id, "executionHistoryDir", executionHistoryDirPath)
			return nil, executionHistoryDirPath, err
		}
	}
	// creating folder for storing output data for this execution history data
	executionHistoryDirPath = impl.createFolderForOutputData(executionHistoryModel.Id)
	err = os.Mkdir(executionHistoryDirPath, commonUtil.DefaultFileCreatePermission)
	if err != nil && !os.IsExist(err) {
		impl.logger.Errorw("error in creating executionHistory directory", "err", err, "executionHistoryId", executionHistoryModel.Id)
		return nil, executionHistoryDirPath, err
	}
	executionHistoryMappingModel := &repository.ScanToolExecutionHistoryMapping{
		ImageScanExecutionHistoryId: executionHistoryModel.Id,
		ScanToolId:                  tool.Id,
		ExecutionStartTime:          executionTimeStart,
		State:                       bean.ScanExecutionProcessStateRunning,
		AuditLog: repository.AuditLog{
			CreatedOn: executionTimeStart,
			CreatedBy: int32(scanEvent.UserId),
			UpdatedOn: executionTimeStart,
			UpdatedBy: int32(scanEvent.UserId),
		},
	}

	err = impl.scanToolExecutionHistoryMappingRepository.Save(executionHistoryMappingModel)
	if err != nil {
		impl.logger.Errorw("Failed to save executionHistoryMappingModel", "err", err)
		return nil, executionHistoryDirPath, err
	}
	return executionHistoryModel, executionHistoryDirPath, nil
}
func DoesFileExist(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
func (impl *ImageScanServiceImpl) processImageScanSbom(scanEvent *common.ImageScanEvent, tool *repository.ScanToolMetadata, executionHistoryId int, output string) error {

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
			ImageScanExecutionHistoryId: []int{executionHistoryId},
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
		info.ImageScanExecutionHistoryId = append(info.ImageScanExecutionHistoryId, executionHistoryId)
		info.UpdatedOn = time.Now()
		err := impl.imageScanDeployInfoRepository.Update(info)
		if err != nil {
			return err
		}
	}
	result := &repository.ResourceScanResult{
		ImageScanExecutionHistoryId: executionHistoryId,
		ScanDataJson:                output,
		Format:                      repository.Json,
		Types:                       []int{repository.Vulnerabilities.ToInt(), repository.License.ToInt()},
		ScanToolId:                  tool.Id,
	}
	err = impl.resourceScanResultRepository.SaveInBatch([]*repository.ResourceScanResult{result})
	if err != nil {
		return err
	}
	return nil
}

func (impl *ImageScanServiceImpl) ProcessScanForTool(tool repository.ScanToolMetadata, executionHistoryDirPath string, executionHistoryId int, userId int32, ctx context.Context, imageScanRenderDto *common.ImageScanRenderDto, isV2 bool) (string, error) {
	imageScanConfig := &ImageScanConfig{}
	err := env.Parse(imageScanConfig)
	if err != nil {
		impl.logger.Errorw("error in parsing env ", "err", err)
		return "", err
	}

	// creating folder for storing this tool output data
	toolIdStr := strconv.Itoa(tool.Id)
	toolOutputDirPath := path.Join(executionHistoryDirPath, toolIdStr)
	err = os.Mkdir(toolOutputDirPath, commonUtil.DefaultFileCreatePermission)
	if err != nil && !os.IsExist(err) {
		impl.logger.Errorw("error in creating toolOutput directory", "err", err, "toolId", tool.Id, "executionHistoryDir", executionHistoryDirPath)
		return "", err
	}
	//getting all steps for this tool
	steps, err := impl.scanToolStepRepository.FindAllByScanToolId(tool.Id)
	if err != nil {
		impl.logger.Errorw("error in getting steps by scan tool id", "err", err, "toolId", tool.Id)
		return "", err
	}
	//sorting steps on the basis of index
	//sort.Slice(steps, func(i, j int) bool { return steps[i].Index < steps[j].Index })
	stepIndexMap := make(map[int]repository.ScanToolStep)
	stepTryCount := make(map[int]int) //map of stepIndex and it's try count
	var stepProcessIndex int

	// Getting and Setting the starting index based of first step for processing starting point on registry type and tool
	registryIndexMappingModel, err := impl.registryIndexMappingRepository.GetStartingIndexForARegistryAndATool(tool.Id, imageScanRenderDto.RegistryType)
	if err != nil {
		impl.logger.Errorw("error in getting registry index mapping", "err", err, "RegistryType", imageScanRenderDto.RegistryType, "toolId", tool.Id)
		return "", err
	}
	stepProcessIndex = registryIndexMappingModel.Index

	for _, step := range steps {
		stepCopy := *step
		if stepCopy.Index == stepCopy.ExecuteStepOnFail {
			stepTryCount[stepCopy.Index] = 1 + stepCopy.RetryCount // adding 1 for the initial try
		} else {
			stepTryCount[stepCopy.Index] = 1 // setting as 1 since only 1 try is needed
		}
		stepIndexMap[stepCopy.Index] = stepCopy
	}
	for {
		if stepTryCount[stepProcessIndex] <= 0 {
			return "", fmt.Errorf("error in completing tool scan process, max no of tries reached for failed step with index : %d", stepProcessIndex)
		}
		step := stepIndexMap[stepProcessIndex]
		//decrementing try count for this step
		stepTryCount[stepProcessIndex] -= 1
		if step.StepExecutionSync {
			output, err := impl.ProcessScanStep(step, tool, toolOutputDirPath, ctx, imageScanRenderDto, isV2)
			if err != nil {
				impl.logger.Errorw("error in processing scan step sync", "err", err, "stepId", step.Id)
				return "", errors.New(string(output))
			}
			if step.StepExecutionType == bean.ScanExecutionTypeCli && step.CliOutputType == cliUtil.CliOutPutTypeStream {
				// read output here for further processing, to update this logic when cli stream processing is made async
				outputFileName := path.Join(toolOutputDirPath, fmt.Sprintf("%d%s", step.Index, bean.JsonOutputFileNameSuffix))
				output, err = commonUtil.ReadFile(outputFileName)
				if err != nil {
					impl.logger.Errorw("error in getting reading output of step", "err", err, "stepOutputFileName", outputFileName)
					return "", err
				}
			}

			isPassed, err := impl.CheckConditionsForAStep(step, output)
			if err != nil {
				impl.logger.Errorw("error in checking conditions for step", "err", err, "stepId", step.Id)
				return "", err
			}
			if !isPassed {
				impl.logger.Infow("conditions not passed for step", "stepId", step.Id)
				return "", fmt.Errorf("conditions not passed for step with index : %d", step.Index)
			}
			if step.ExecuteStepOnPass == bean.NullProcessIndex && isPassed {

				if isV2 {
					return string(output), nil
				}

				//step process is passed and scanning is completed
				err = impl.ConvertEndStepOutputAndSaveVulnerabilities(output, executionHistoryId, tool, step, userId)
				if err != nil {
					impl.logger.Errorw("error in saving vulnerabilities", "err", err)
					return "", err
				}
				return string(output), nil
			} else if step.ExecuteStepOnFail == bean.NullProcessIndex && !isPassed { //step process is failed and scanning is completed
				return "", fmt.Errorf("error in executing step with index : %d", stepProcessIndex)
			} else if isPassed { //step process is passed and have to move to next step for processing
				stepProcessIndex = step.ExecuteStepOnPass
			} else if !isPassed { //step process is failed and have to move to next step for processing
				stepProcessIndex = step.ExecuteStepOnFail //this step can be equal to the same step in case of retry or can be other one
			}
		} else { //async type processing
			cxtx, cancel := context.WithTimeout(ctx, time.Duration(imageScanConfig.ScanImageAsyncTimeout)*time.Minute)
			defer cancel()
			go func() {
				//will not check if step is passed or failed
				_, err := impl.ProcessScanStep(step, tool, toolOutputDirPath, cxtx, nil, false)
				if err != nil {
					impl.logger.Errorw("error in processing scan step async", "err", err, "stepId", step.Id)
					return
				}
			}()
			stepProcessIndex = step.ExecuteStepOnPass      // for async type process, always considering step to be passed
			if stepProcessIndex == bean.NullProcessIndex { // if end step, consider it completed and return
				return "", nil
			}
		}
	}
}

func (impl *ImageScanServiceImpl) ProcessScanStep(step repository.ScanToolStep, tool repository.ScanToolMetadata, toolOutputDirPath string, ctx context.Context, imageScanRenderDto *common.ImageScanRenderDto, isV2 bool) ([]byte, error) {
	outputFileNameForThisStep := path.Join(toolOutputDirPath, fmt.Sprintf("%d%s", step.Index, bean.JsonOutputFileNameSuffix))
	var output []byte
	if step.StepExecutionType == bean.ScanExecutionTypeHttp {
		queryParams, httpHeaders, inputPayload, err := impl.GetHttpStepInputParams(step, toolOutputDirPath, nil)
		if err != nil {
			impl.logger.Errorw("error in getting http step input params", "err", err)
			return nil, err
		}
		output, err = httpUtil.HandleHTTPRequest(tool.ServerBaseUrl, step.HttpMethodType, httpHeaders, queryParams, inputPayload, outputFileNameForThisStep, ctx)
		if err != nil {
			impl.logger.Errorw("error in http request txn", "err", err)
			return nil, err
		}
	} else if step.StepExecutionType == bean.ScanExecutionTypeCli {
		extraArgs := ""
		if isV2 {
			extraArgs = "--scanners vuln,config,secret,license  --license-full"
		}

		imageScanRenderDto.OutputFilePath = outputFileNameForThisStep
		renderedCommand, err := impl.GetCliInputParams(step, toolOutputDirPath, imageScanRenderDto, tool.ToolMetaData, extraArgs)
		if err != nil {
			impl.logger.Errorw("error in getting cli step input params", "err", err)
			return nil, err
		}
		output, err = cliUtil.HandleCliRequest(renderedCommand, outputFileNameForThisStep, ctx, step.CliOutputType, nil)
		if err != nil {
			impl.logger.Errorw("error in cli request txn", "err", err)
			return output, err
		}
	}
	return output, nil
}

func (impl *ImageScanServiceImpl) ConvertEndStepOutputAndSaveVulnerabilities(stepOutput []byte, executionHistoryId int, tool repository.ScanToolMetadata, step repository.ScanToolStep, userId int32) error {
	var vulnerabilities []*bean.ImageScanOutputObject
	var err error
	impl.logger.Debugw("ConvertEndStepOutputAndSaveVulnerabilities", "stepOutput", string(stepOutput), "resultDescriptorTemplate", tool.ResultDescriptorTemplate)
	if isV1Template(tool.ResultDescriptorTemplate) { // result descriptor template is go template, go with v1 logic
		vulnerabilities, err = impl.getImageScanOutputObjectsV1(stepOutput, tool.ResultDescriptorTemplate)
		if err != nil {
			impl.logger.Errorw("error, getImageScanOutputObjectsV1", "err", err, "stepOutput", stepOutput, "resultDescriptorTemplate", tool.ResultDescriptorTemplate)
			return err
		}
	} else { //not go template, go with v2 logic
		vulnerabilities, err = impl.getImageScanOutputObjectsV2(stepOutput, tool.ResultDescriptorTemplate)
		if err != nil {
			impl.logger.Errorw("error, getImageScanOutputObjectsV2", "err", err, "stepOutput", stepOutput, "resultDescriptorTemplate", tool.ResultDescriptorTemplate)
			return err
		}
	}

	allCvesMap := make([]*repository.CveStore, 0, len(vulnerabilities))
	cvesToBeSaved := make([]*repository.CveStore, 0, len(vulnerabilities))
	uniqueVulnerabilityMap := make(map[string]*bean.ImageScanOutputObject)
	allCvesNames := make([]string, 0, len(vulnerabilities))
	for _, vul := range vulnerabilities {
		if _, ok := uniqueVulnerabilityMap[vul.Name]; !ok {
			uniqueVulnerabilityMap[vul.Name] = vul
			allCvesNames = append(allCvesNames, vul.Name)
		}
	}
	allSavedCvesMap := make(map[string]*repository.CveStore)
	if len(allCvesNames) > 0 {
		allSavedCves, err := impl.cveStoreRepository.FindByCveNames(allCvesNames)
		if err != nil {
			if err == pg.ErrNoRows {
				// in case of no cve found , just ignore
				impl.logger.Infow("no saved cves found", err)
			} else {
				impl.logger.Errorw("error in getting all cves ", "err", err)
				return err
			}
		}

		for _, cve := range allSavedCves {
			allSavedCvesMap[cve.Name] = cve
		}
	}
	for _, vul := range uniqueVulnerabilityMap {
		var cve *repository.CveStore
		if val, ok := allSavedCvesMap[vul.Name]; ok {
			cve = val
		}
		if cve == nil {
			cve = &repository.CveStore{
				Name:         vul.Name,
				Package:      vul.Package,
				Version:      vul.PackageVersion,
				FixedVersion: vul.FixedInVersion,
			}
			lowerCaseSeverity := bean.ConvertToLowerCase(vul.Severity)
			cve.Severity = bean.ConvertToSeverityUtility(lowerCaseSeverity)
			cve.StandardSeverity = bean.ConvertToStandardSeverityUtility(lowerCaseSeverity)
			cve.CreatedOn = time.Now()
			cve.CreatedBy = userId
			cve.UpdatedOn = time.Now()
			cve.UpdatedBy = userId
			cvesToBeSaved = append(cvesToBeSaved, cve)
		}
		allCvesMap = append(allCvesMap, cve)
	}

	imageScanExecutionResults := make([]*repository.ImageScanExecutionResult, 0, len(allCvesMap))
	for _, cve := range allCvesMap {
		imageScanExecutionResult := &repository.ImageScanExecutionResult{
			ImageScanExecutionHistoryId: executionHistoryId,
			CveStoreName:                cve.Name,
			ScanToolId:                  tool.Id,
		}
		imageScanExecutionResults = append(imageScanExecutionResults, imageScanExecutionResult)
	}
	tx, err := impl.cveStoreRepository.GetConnection().Begin()
	if err != nil {
		impl.logger.Errorw("error in initiating db transaction", "err", err)
		return err
	}
	// Rollback tx on error.
	defer tx.Rollback()
	if len(cvesToBeSaved) > 0 {
		err = impl.cveStoreRepository.SaveInBatch(cvesToBeSaved, tx)
		if err != nil {
			impl.logger.Errorw("error in saving cves in batch", "err", err)
			return err
		}
	}
	if len(imageScanExecutionResults) > 0 {
		err = impl.scanResultRepository.SaveInBatch(imageScanExecutionResults, tx)
		if err != nil {
			impl.logger.Errorw("error in saving scan execution results", "err", err)
			return err
		}
	}
	err = tx.Commit()
	if err != nil {
		impl.logger.Errorw("error in committing transaction", "err", err)
		return err
	}
	return nil
}

func isV1Template(resultDescriptorTemplate string) bool {
	var mappings []bean.Mapping
	err := json.Unmarshal([]byte(resultDescriptorTemplate), &mappings)
	return err != nil && isValidGoTemplate(resultDescriptorTemplate) //checking error too because our new result descriptor template can pass go templating too as it contains a simple json
}

func isValidGoTemplate(templateStr string) bool {
	_, err := template.New("test").Funcs(template.FuncMap{ //for trivy we use add function, so it needs to be defined here
		"add": func(a, b int) int { return a + b },
	}).Parse(templateStr)
	return err == nil
}

func (impl *ImageScanServiceImpl) getImageScanOutputObjectsV1(stepOutput []byte, resultDescriptorTemplate string) ([]*bean.ImageScanOutputObject, error) {
	//rendering image descriptor template with output json to get vulnerabilities updated
	renderedTemplate, err := commonUtil.ParseJsonTemplate(resultDescriptorTemplate, stepOutput)
	if err != nil {
		impl.logger.Errorw("error in parsing template to get vulnerabilities", "err", err)
		return nil, err
	}
	renderedTemplate = common.RemoveTrailingComma(renderedTemplate)
	var vulnerabilities []*bean.ImageScanOutputObject
	err = json.Unmarshal([]byte(renderedTemplate), &vulnerabilities)
	if err != nil {
		impl.logger.Errorw("error in unmarshalling rendered template", "err", err)
		return nil, err
	}
	return vulnerabilities, nil
}

func (impl *ImageScanServiceImpl) getImageScanOutputObjectsV2(stepOutput []byte, resultDescriptorTemplate string) ([]*bean.ImageScanOutputObject, error) {
	var vulnerabilities []*bean.ImageScanOutputObject
	var mappings []bean.Mapping
	err := json.Unmarshal([]byte(resultDescriptorTemplate), &mappings)
	if err != nil {
		impl.logger.Errorw("error in un-marshaling result descriptor template", "err", err, "resultDescriptorTemplate", resultDescriptorTemplate)
		return nil, err
	}
	var processArray func(mapping bean.Mapping, value gjson.Result)
	processArray = func(mapping bean.Mapping, value gjson.Result) {
		value.ForEach(func(_, nestedValue gjson.Result) bool {
			if nestedValue.IsArray() {
				// if the nested value is an array, recursively process it
				processArray(mapping, nestedValue)
			} else {
				vulnerability := &bean.ImageScanOutputObject{
					Name:           nestedValue.Get(mapping[bean.MappingKeyName]).String(),
					Package:        nestedValue.Get(mapping[bean.MappingKeyPackage]).String(),
					PackageVersion: nestedValue.Get(mapping[bean.MappingKeyPackageVersion]).String(),
					FixedInVersion: nestedValue.Get(mapping[bean.MappingKeyFixedInVersion]).String(),
					Severity:       nestedValue.Get(mapping[bean.MappingKeySeverity]).String(),
				}
				vulnerabilities = append(vulnerabilities, vulnerability)
			}
			return true
		})
	}
	for _, mapping := range mappings {
		result := gjson.Get(string(stepOutput), mapping[bean.MappingKeyPathToVulnerabilitiesArray])
		if !result.Exists() {
			continue
		}
		processArray(mapping, result)
	}
	impl.logger.Debugw("received vulnerabilities", "vulnerabilites", vulnerabilities)
	return vulnerabilities, nil
}

func (impl *ImageScanServiceImpl) GetHttpStepInputParams(step repository.ScanToolStep, toolOutputDirPath string, imageScanRenderDto *common.ImageScanRenderDto) (url.Values, map[string]string, *bytes.Buffer, error) {
	var err error
	var queryParams url.Values
	httpHeaders := make(map[string]string)
	inputPayload := &bytes.Buffer{}
	inputPayloadBytes := step.HttpInputPayload
	if step.HttpQueryParams != nil {
		err = json.Unmarshal(step.HttpQueryParams, &queryParams)
		if err != nil {
			impl.logger.Errorw("error in unmarshalling query params", "err", err)
			return queryParams, httpHeaders, inputPayload, err
		}
	}
	if step.HttpReqHeaders != nil {
		err = json.Unmarshal(step.HttpReqHeaders, &httpHeaders)
		if err != nil {
			impl.logger.Errorw("error in unmarshalling http headers", "err", err)
			return queryParams, httpHeaders, inputPayload, err
		}
	}
	inputPayloadBytes, err = impl.RenderInputDataForAStep(string(step.HttpInputPayload), step.RenderInputDataFromStep, toolOutputDirPath, imageScanRenderDto, "", "")
	if err != nil {
		impl.logger.Errorw("error in rendering http input payload", "err", err)
		return queryParams, httpHeaders, inputPayload, err
	}
	inputPayload = bytes.NewBuffer(inputPayloadBytes)
	return queryParams, httpHeaders, inputPayload, nil
}

func (impl *ImageScanServiceImpl) GetCliInputParams(step repository.ScanToolStep, toolOutputDirPath string, imageScanRenderDto *common.ImageScanRenderDto, toolMetaData string, extraArgs string) (string, error) {
	var err error
	var renderedCommand []byte
	renderedCommand, err = impl.RenderInputDataForAStep(step.CliCommand, step.RenderInputDataFromStep, toolOutputDirPath, imageScanRenderDto, toolMetaData, extraArgs)
	if err != nil {
		impl.logger.Errorw("error in rendering cli input args", "err", err)
		return "", err
	}
	return string(renderedCommand), nil
}

func (impl *ImageScanServiceImpl) RenderInputDataForAStep(inputPayloadTmpl string, outputStepIndex int, toolExecutionDirectoryPath string, imageScanRenderDto *common.ImageScanRenderDto, toolMetaData string, extraArgs string) ([]byte, error) {
	tmpl := template.Must(template.New("").Parse(inputPayloadTmpl))
	jsonMap := map[string]interface{}{}
	metaDataMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(toolMetaData), &metaDataMap)
	if err != nil {
		impl.logger.Errorw("error in unmarshalling meta data ", "err", err, "toolMetaData", toolMetaData)
		return nil, err
	}
	if outputStepIndex != bean.NullProcessIndex {
		outputFileName := path.Join(toolExecutionDirectoryPath, fmt.Sprintf("%d%s", outputStepIndex, bean.JsonOutputFileNameSuffix))
		outputFromStep, err := commonUtil.ReadFile(outputFileName)
		if err != nil {
			impl.logger.Errorw("error in getting reading output of step", "err", err, "stepOutputFileName", outputFromStep)
			return nil, err
		}
		err = json.Unmarshal(outputFromStep, &jsonMap)
		if err != nil {
			impl.logger.Errorw("error in unmarshalling", "err", err)
			return nil, err
		}
	}
	//entering imageScanRenderData in above json map; TODO: update this to some other logic to handle more fields in future
	jsonMap[common.AWSSecretAccessKey] = imageScanRenderDto.AWSSecretAccessKey
	jsonMap[common.AWSAccessKeyId] = imageScanRenderDto.AWSAccessKeyId
	jsonMap[common.AWSRegion] = imageScanRenderDto.AWSRegion
	jsonMap[common.Username] = imageScanRenderDto.Username
	jsonMap[common.Password] = imageScanRenderDto.Password
	jsonMap[common.GCR_FILE_PATH] = toolExecutionDirectoryPath
	jsonMap[common.IMAGE_NAME] = imageScanRenderDto.Image
	jsonMap[common.OUTPUT_FILE_PATH] = imageScanRenderDto.OutputFilePath
	jsonMap[common.EXTRA_ARGS] = extraArgs

	for key, val := range metaDataMap {
		jsonMap[key] = val
	}
	buf := &bytes.Buffer{}
	err = tmpl.Execute(buf, jsonMap)
	if err != nil {
		impl.logger.Errorw("error in executing template", "err", err)
		return nil, err
	}
	return buf.Bytes(), nil
}

func (impl *ImageScanServiceImpl) CreateScanExecutionRegistryForClairV4(vs []*claircore.Vulnerability, event *common.ImageScanEvent, toolId int, executionHistory *repository.ImageScanExecutionHistory) ([]*claircore.Vulnerability, error) {

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
				Package:      item.Package.Name,
				Version:      item.Package.Version,
				FixedVersion: item.FixedInVersion,
			}
			lowerCaseSeverity := bean.ConvertToLowerCase(item.Severity)
			cveStore.Severity = bean.ConvertToSeverityUtility(lowerCaseSeverity)
			cveStore.StandardSeverity = bean.ConvertToStandardSeverityUtility(lowerCaseSeverity)
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
	for _, cveName := range cveNames {
		imageScanExecutionResult := &repository.ImageScanExecutionResult{
			ImageScanExecutionHistoryId: executionHistory.Id,
			CveStoreName:                cveName,
			ScanToolId:                  toolId,
		}
		err := impl.scanResultRepository.Save(imageScanExecutionResult)
		if err != nil {
			impl.logger.Errorw("Failed to save cve", "err", err)
			return nil, err
		}
	}
	return vs, nil
}

func (impl *ImageScanServiceImpl) CreateScanExecutionRegistryForClairV2(vs []*clair.Vulnerability, event *common.ImageScanEvent, toolId int, executionHistory *repository.ImageScanExecutionHistory) ([]*clair.Vulnerability, error) {

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
			lowerCaseSeverity := bean.ConvertToLowerCase(item.Severity)
			cveStore.Severity = bean.ConvertToSeverityUtility(lowerCaseSeverity)
			cveStore.StandardSeverity = bean.ConvertToStandardSeverityUtility(lowerCaseSeverity)
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
	for _, cveName := range cveNames {
		imageScanExecutionResult := &repository.ImageScanExecutionResult{
			ImageScanExecutionHistoryId: executionHistory.Id,
			CveStoreName:                cveName,
			ScanToolId:                  toolId,
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
	scanHistoryId := 0
	if scanHistory != nil {
		scanHistoryId = scanHistory.Id
		//scanned = true
	}
	if scanHistoryId > 0 {
		scanHistoryMappings, err := impl.scanToolExecutionHistoryMappingRepository.GetAllScanHistoriesByExecutionHistoryIdAndStates(scanHistoryId, []bean.ScanExecutionProcessState{bean.ScanExecutionProcessStateRunning, bean.ScanExecutionProcessStateCompleted})
		if err != nil && err != pg.ErrNoRows {
			impl.logger.Errorw("error in getting history mappings", "err", err)
			return scanned, err
		}
		if len(scanHistoryMappings) > 0 {
			scanned = true
		}
	}

	return scanned, err
}

func (impl *ImageScanServiceImpl) CheckConditionsForAStep(step repository.ScanToolStep, stepOutput []byte) (bool, error) {
	//get all conditions for a step
	conditions, err := impl.scanStepConditionRepository.FindAllByToolStepId(step.Id)
	if err != nil {
		impl.logger.Errorw("error in getting all conditions by step id", "err", err, "stepId", step.Id)
		return false, err
	}
	for _, condition := range conditions {
		isPassedForCondition, err := impl.EvaluateCondition(*condition, stepOutput)
		if err != nil {
			impl.logger.Errorw("error in evaluating condition", "err", err, "condition", condition)
			return false, err
		}
		if !isPassedForCondition { //condition failed, will not check further
			return false, nil
		}
	}
	return true, nil
}

func (impl *ImageScanServiceImpl) EvaluateCondition(condition repository.ScanStepCondition, stepOutput []byte) (bool, error) {
	expression, err := govaluate.NewEvaluableExpression(fmt.Sprintf("conditionOn %s conditionalVal", condition.ConditionalOperator))
	if err != nil {
		return false, err
	}
	conditionOnRaw := gjson.Get(string(stepOutput), condition.ConditionOn).String()
	conditionOn, err := bean.ConvertVariableFormat(conditionOnRaw, condition.ConditionVariableFormat)
	if err != nil {
		return false, err
	}
	conditionVal, err := bean.ConvertVariableFormat(condition.ConditionalValue, condition.ConditionVariableFormat)
	if err != nil {
		return false, err
	}
	parameters := make(map[string]interface{}, 2)
	parameters["conditionOn"] = conditionOn
	parameters["conditionalVal"] = conditionVal
	evaluation, err := expression.Evaluate(parameters)
	if err != nil {
		return false, err
	}
	isPassed := evaluation.(bool)
	return isPassed, nil
}

func (impl *ImageScanServiceImpl) handleProgressingScans() {
	//marking all scans failed which have crossed try count
	err := impl.scanToolExecutionHistoryMappingRepository.MarkAllRunningStateAsFailedHavingTryCountReachedLimit(impl.imageScanConfig.ScanTryCount)
	if err != nil {
		impl.logger.Errorw("error in marking all running scan states as failed", "err", err)
		return
	}

	//getting all scans which are in progressing after marking failed
	scanHistories, err := impl.scanToolExecutionHistoryMappingRepository.GetAllScanHistoriesByState(bean.ScanExecutionProcessStateRunning)
	if err != nil {
		impl.logger.Errorw("error in getting all scans by running state", "err", err)
		return
	}

	var executionHistoryDirPath string
	flagForDeleting := false
	// Create Folder for output data for execution history only if any pending scans are there due to pod died
	if len(scanHistories) > 0 {
		flagForDeleting = true
		executionHistoryDirPath = impl.createFolderForOutputData(scanHistories[0].ImageScanExecutionHistoryId)
	}
	wg := &sync.WaitGroup{}
	wg.Add(len(scanHistories))
	imagescanExecutionHistories, err := impl.scanHistoryRepository.FindAll()
	if err != nil {
		impl.logger.Errorw("error in getting scan histories on start up", "err", err)
		return
	}
	imageScanToolMetadatas, err := impl.scanToolMetadataRepository.FindAllActiveTools()
	if err != nil {
		impl.logger.Errorw("error in getting all active tools", "err", err)
	}
	imageScanExecutionHistoryMap := make(map[int]*repository.ImageScanExecutionHistory)
	imageScanToolsMap := make(map[int]*repository.ScanToolMetadata)

	for _, imageScanExecutionHistory := range imagescanExecutionHistories {
		imageScanExecutionHistoryMap[imageScanExecutionHistory.Id] = imageScanExecutionHistory
	}
	for _, imageScanToolMetaData := range imageScanToolMetadatas {
		imageScanToolsMap[imageScanToolMetaData.Id] = imageScanToolMetaData
	}

	//System doing image scanning for all pending scans
	for _, scanHistory := range scanHistories {
		scanEvent := common.ImageScanEvent{}
		scanEventJson := imageScanExecutionHistoryMap[scanHistory.ImageScanExecutionHistoryId].SourceMetadataJson
		if len(scanEventJson) == 0 {
			return
		}
		scanTool := imageScanToolsMap[scanHistory.ScanToolId]
		err = json.Unmarshal([]byte(scanEventJson), &scanHistory)
		if err != nil {
			impl.logger.Errorw("error in un-marshaling", "err", err)
			return
		}
		imageScanRenderDto, err := impl.getImageScanRenderDto(scanEvent.DockerRegistryId, scanEvent.Image)
		if err != nil {
			impl.logger.Errorw("service error, getImageScanRenderDto", "err", err, "dockerRegistryId", scanEvent.DockerRegistryId)
			return
		}
		_, err = impl.scanImageForTool(scanTool, scanHistory.ImageScanExecutionHistoryId, executionHistoryDirPath, wg, 1, nil, imageScanRenderDto, false)
		if err != nil {
			impl.logger.Errorw("error in scanning image", "err", err)
			return
		}
	}
	wg.Wait()

	//deleting executionDirectoryPath
	if flagForDeleting {
		err = os.Remove(executionHistoryDirPath)
		if err != nil {
			impl.logger.Errorw("error in deleting executionHistoryDirectory", "err", err, "executionHistoryDirPath", executionHistoryDirPath)
		}
	}

}

func GetImageScannerConfig() (*ImageScanConfig, error) {
	scannerConfig := &ImageScanConfig{}
	err := env.Parse(scannerConfig)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("could not get scanner config from environment :%v", err))
	}
	return scannerConfig, err
}

type ImageScanConfig struct {
	ScannerType           string `env:"SCANNER_TYPE" envDefault:""`
	ScanTryCount          int    `env:"IMAGE_SCAN_TRY_COUNT" envDefault:"1"`
	ScanImageTimeout      int    `env:"IMAGE_SCAN_TIMEOUT" envDefault:"10"`      // Time is considered in minutes
	ScanImageAsyncTimeout int    `env:"IMAGE_SCAN_ASYNC_TIMEOUT" envDefault:"3"` // Time is considered in minutes
}
