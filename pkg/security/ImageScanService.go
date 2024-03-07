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
	"github.com/devtron-labs/image-scanner/internals/sql/bean"
	"github.com/devtron-labs/image-scanner/internals/sql/repository"
	cliUtil "github.com/devtron-labs/image-scanner/internals/step-lib/util/cli-util"
	commonUtil "github.com/devtron-labs/image-scanner/internals/step-lib/util/common-util"
	httpUtil "github.com/devtron-labs/image-scanner/internals/step-lib/util/http-util"
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
	ScanImageForTool(tool *repository.ScanToolMetadata, executionHistoryId int, executionHistoryDirPathCopy string, wg *sync.WaitGroup, userId int32, ctx context.Context, imageScanRenderDto *common.ImageScanRenderDto, proxyUrl string) error
	CreateFolderForOutputData(executionHistoryModelId int) string
	HandleProgressingScans()
	GetActiveTool() (*repository.ScanToolMetadata, error)
	RegisterScanExecutionHistoryAndState(scanEvent *common.ImageScanEvent, tool *repository.ScanToolMetadata) (*repository.ImageScanExecutionHistory, string, error)
	GetImageScanRenderDto(registryId string, image string) (*common.ImageScanRenderDto, error)
	FetchProxyUrl(scanEvent *common.ImageScanEvent) string
	FetchProxyEnvForCliRequest(proxyUrl string) []string
}

type ImageScanServiceImpl struct {
	Logger                                    *zap.SugaredLogger
	ScanHistoryRepository                     repository.ImageScanHistoryRepository
	ScanResultRepository                      repository.ImageScanResultRepository
	ScanObjectMetaRepository                  repository.ImageScanObjectMetaRepository
	CveStoreRepository                        repository.CveStoreRepository
	ImageScanDeployInfoRepository             repository.ImageScanDeployInfoRepository
	CiArtifactRepository                      repository.CiArtifactRepository
	ScanToolExecutionHistoryMappingRepository repository.ScanToolExecutionHistoryMappingRepository
	ScanToolMetadataRepository                repository.ScanToolMetadataRepository
	ScanStepConditionRepository               repository.ScanStepConditionRepository
	ScanToolStepRepository                    repository.ScanToolStepRepository
	ScanStepConditionMappingRepository        repository.ScanStepConditionMappingRepository
	ImageScanConfig                           *ImageScanConfig
	DockerArtifactStoreRepository             repository.DockerArtifactStoreRepository
	RegistryIndexMappingRepository            repository.RegistryIndexMappingRepository
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
	dockerArtifactStoreRepository repository.DockerArtifactStoreRepository, registryIndexMappingRepository repository.RegistryIndexMappingRepository) *ImageScanServiceImpl {
	imageScanService := &ImageScanServiceImpl{Logger: logger, ScanHistoryRepository: scanHistoryRepository, ScanResultRepository: scanResultRepository,
		ScanObjectMetaRepository: scanObjectMetaRepository, CveStoreRepository: cveStoreRepository,
		ImageScanDeployInfoRepository:             imageScanDeployInfoRepository,
		CiArtifactRepository:                      ciArtifactRepository,
		ScanToolExecutionHistoryMappingRepository: scanToolExecutionHistoryMappingRepository,
		ScanToolMetadataRepository:                scanToolMetadataRepository,
		ScanStepConditionRepository:               scanStepConditionRepository,
		ScanToolStepRepository:                    scanToolStepRepository,
		ScanStepConditionMappingRepository:        scanStepConditionMappingRepository,
		ImageScanConfig:                           imageScanConfig,
		DockerArtifactStoreRepository:             dockerArtifactStoreRepository,
		RegistryIndexMappingRepository:            registryIndexMappingRepository,
	}
	imageScanService.HandleProgressingScans()
	return imageScanService
}

func (impl *ImageScanServiceImpl) FetchProxyEnvForCliRequest(proxyUrl string) []string {
	var proxyEnv []string
	return proxyEnv
}

func (impl *ImageScanServiceImpl) GetActiveTool() (*repository.ScanToolMetadata, error) {
	//get active tool
	tool, err := impl.ScanToolMetadataRepository.FindActiveToolByScanTarget(repository.ImageScanTargetType)
	if err != nil {
		impl.Logger.Errorw("error in getting active tool by scan target", "err", err, "scanTarget", repository.ImageScanTargetType)
		return nil, err
	}
	return tool, nil
}

func (impl *ImageScanServiceImpl) FetchProxyUrl(scanEvent *common.ImageScanEvent) string {
	return ""
}

func (impl *ImageScanServiceImpl) ScanImage(scanEvent *common.ImageScanEvent, tool *repository.ScanToolMetadata, executionHistory *repository.ImageScanExecutionHistory, executionHistoryDirPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(impl.ImageScanConfig.ScanImageTimeout)*time.Minute)
	defer cancel()
	//checking if image is already scanned or not
	isImageScanned, err := impl.IsImageScanned(scanEvent.Image)
	if err != nil && err != pg.ErrNoRows {
		impl.Logger.Errorw("error in fetching scan history ", "err", err, "image", scanEvent.Image)
		return err
	}
	if isImageScanned {
		impl.Logger.Infow("image already scanned, skipping further process", "image", scanEvent.Image)
		return nil
	}
	imageScanRenderDto, err := impl.GetImageScanRenderDto(scanEvent.DockerRegistryId, scanEvent.Image)
	if err != nil {
		impl.Logger.Errorw("service error, GetImageScanRenderDto", "err", err, "dockerRegistryId", scanEvent.DockerRegistryId)
		return err
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	proxyUrl := impl.FetchProxyUrl(scanEvent)
	// TODO: if multiple processes are to be done in parallel, then error propagation should have to be done via channels
	err = impl.ScanImageForTool(tool, executionHistory.Id, executionHistoryDirPath, wg, int32(scanEvent.UserId), ctx, imageScanRenderDto, proxyUrl)
	if err != nil {
		impl.Logger.Errorw("err in scanning image", "err", err, "tool", tool, "executionHistory.Id", executionHistory.Id, "executionHistoryDirPath", executionHistoryDirPath, "scanEvent.UserId", scanEvent.UserId)
		return err
	}
	wg.Wait()
	return err
}

func (impl *ImageScanServiceImpl) GetImageScanRenderDto(registryId string, image string) (*common.ImageScanRenderDto, error) {
	dockerRegistry, err := impl.DockerArtifactStoreRepository.FindById(registryId)
	if err != nil {
		impl.Logger.Errorw("error in getting docker registry by id", "err", err, "id", registryId)
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
func (impl *ImageScanServiceImpl) ScanImageForTool(tool *repository.ScanToolMetadata, executionHistoryId int,
	executionHistoryDirPathCopy string, wg *sync.WaitGroup, userId int32, ctx context.Context, imageScanRenderDto *common.ImageScanRenderDto, proxyUrl string) error {
	toolCopy := *tool
	var processedState bean.ScanExecutionProcessState
	err := impl.ProcessScanForTool(toolCopy, executionHistoryDirPathCopy, executionHistoryId, userId, ctx, imageScanRenderDto, proxyUrl)
	if err != nil {
		impl.Logger.Errorw("error in processing scan for tool:", toolCopy.Name, "err", err)
		processedState = bean.ScanExecutionProcessStateFailed
	} else {
		processedState = bean.ScanExecutionProcessStateCompleted
	}
	updateErr := impl.ScanToolExecutionHistoryMappingRepository.UpdateStateByToolAndExecutionHistoryId(executionHistoryId, toolCopy.Id, processedState, time.Now())
	if updateErr != nil {
		impl.Logger.Errorw("error in UpdateStateByToolAndExecutionHistoryId", "err", err)
		err = updateErr
	}
	wg.Done()
	return err
}
func (impl *ImageScanServiceImpl) CreateFolderForOutputData(executionHistoryModelId int) string {
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
		impl.Logger.Errorw("error in marshalling scanEvent", "err", err, "event", scanEvent)
		return nil, "", err
	}
	executionHistoryModel := &repository.ImageScanExecutionHistory{
		Image:         scanEvent.Image,
		ImageHash:     scanEvent.ImageDigest,
		ExecutionTime: executionTimeStart,
		ExecutedBy:    scanEvent.UserId,
		ScanEventJson: string(scanEventJson),
	}
	err = impl.ScanHistoryRepository.Save(executionHistoryModel)
	if err != nil {
		impl.Logger.Errorw("Failed to save executionHistory", "err", err, "model", executionHistoryModel)
		return nil, executionHistoryDirPath, err
	}
	// creating folder for storing all details if not exist
	isExist, err := DoesFileExist(bean.ScanOutputDirectory)
	if err != nil {
		impl.Logger.Errorw("error in checking if scan output directory exist ", "err", err)
		return nil, executionHistoryDirPath, err
	}
	if !isExist {
		err = os.Mkdir(bean.ScanOutputDirectory, commonUtil.DefaultFileCreatePermission)
		if err != nil && !os.IsExist(err) {
			impl.Logger.Errorw("error in creating Output directory", "err", err, "toolId", tool.Id, "executionHistoryDir", executionHistoryDirPath)
			return nil, executionHistoryDirPath, err
		}
	}
	// creating folder for storing output data for this execution history data
	executionHistoryDirPath = impl.CreateFolderForOutputData(executionHistoryModel.Id)
	err = os.Mkdir(executionHistoryDirPath, commonUtil.DefaultFileCreatePermission)
	if err != nil && !os.IsExist(err) {
		impl.Logger.Errorw("error in creating executionHistory directory", "err", err, "executionHistoryId", executionHistoryModel.Id)
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

	err = impl.ScanToolExecutionHistoryMappingRepository.Save(executionHistoryMappingModel)
	if err != nil {
		impl.Logger.Errorw("Failed to save executionHistoryMappingModel", "err", err)
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
func (impl *ImageScanServiceImpl) ProcessScanForTool(tool repository.ScanToolMetadata, executionHistoryDirPath string, executionHistoryId int, userId int32, ctx context.Context, imageScanRenderDto *common.ImageScanRenderDto, proxyUrl string) error {
	imageScanConfig := &ImageScanConfig{}
	err := env.Parse(imageScanConfig)
	if err != nil {
		impl.Logger.Errorw("error in parsing env ", "err", err)
		return err
	}

	// creating folder for storing this tool output data
	toolIdStr := strconv.Itoa(tool.Id)
	toolOutputDirPath := path.Join(executionHistoryDirPath, toolIdStr)
	err = os.Mkdir(toolOutputDirPath, commonUtil.DefaultFileCreatePermission)
	if err != nil && !os.IsExist(err) {
		impl.Logger.Errorw("error in creating toolOutput directory", "err", err, "toolId", tool.Id, "executionHistoryDir", executionHistoryDirPath)
		return err
	}
	//getting all steps for this tool
	steps, err := impl.ScanToolStepRepository.FindAllByScanToolId(tool.Id)
	if err != nil {
		impl.Logger.Errorw("error in getting steps by scan tool id", "err", err, "toolId", tool.Id)
		return err
	}
	//sorting steps on the basis of index
	//sort.Slice(steps, func(i, j int) bool { return steps[i].Index < steps[j].Index })
	stepIndexMap := make(map[int]repository.ScanToolStep)
	stepTryCount := make(map[int]int) //map of stepIndex and it's try count
	var stepProcessIndex int

	// Getting and Setting the starting index based of first step for processing starting point on registry type and tool
	registryIndexMappingModel, err := impl.RegistryIndexMappingRepository.GetStartingIndexForARegistryAndATool(tool.Id, imageScanRenderDto.RegistryType)
	if err != nil {
		impl.Logger.Errorw("error in getting registry index mapping", "err", err, "RegistryType", imageScanRenderDto.RegistryType, "toolId", tool.Id)
		return err
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
			return fmt.Errorf("error in completing tool scan process, max no of tries reached for failed step with index : %d", stepProcessIndex)
		}
		step := stepIndexMap[stepProcessIndex]
		//decrementing try count for this step
		stepTryCount[stepProcessIndex] -= 1
		if step.StepExecutionSync {
			output, err := impl.ProcessScanStep(step, tool, toolOutputDirPath, ctx, imageScanRenderDto, proxyUrl)
			if err != nil {
				impl.Logger.Errorw("error in processing scan step sync", "err", err, "stepId", step.Id)
				return err
			}
			if step.StepExecutionType == bean.ScanExecutionTypeCli && step.CliOutputType == cliUtil.CliOutPutTypeStream {
				// read output here for further processing, to update this logic when cli stream processing is made async
				outputFileName := path.Join(toolOutputDirPath, fmt.Sprintf("%d%s", step.Index, bean.JsonOutputFileNameSuffix))
				output, err = commonUtil.ReadFile(outputFileName)
				if err != nil {
					impl.Logger.Errorw("error in getting reading output of step", "err", err, "stepOutputFileName", outputFileName)
					return err
				}
			}

			isPassed, err := impl.CheckConditionsForAStep(step, output)
			if err != nil {
				impl.Logger.Errorw("error in checking conditions for step", "err", err, "stepId", step.Id)
				return err
			}
			if !isPassed {
				impl.Logger.Infow("conditions not passed for step", "stepId", step.Id)
				return fmt.Errorf("conditions not passed for step with index : %d", step.Index)
			}
			if step.ExecuteStepOnPass == bean.NullProcessIndex && isPassed { //step process is passed and scanning is completed
				err = impl.ConvertEndStepOutputAndSaveVulnerabilities(output, executionHistoryId, tool, step, userId)
				if err != nil {
					impl.Logger.Errorw("error in saving vulnerabilities", "err", err)
					return err
				}
				return nil
			} else if step.ExecuteStepOnFail == bean.NullProcessIndex && !isPassed { //step process is failed and scanning is completed
				return fmt.Errorf("error in executing step with index : %d", stepProcessIndex)
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
				_, err := impl.ProcessScanStep(step, tool, toolOutputDirPath, cxtx, nil, proxyUrl)
				if err != nil {
					impl.Logger.Errorw("error in processing scan step async", "err", err, "stepId", step.Id)
					return
				}
			}()
			stepProcessIndex = step.ExecuteStepOnPass      // for async type process, always considering step to be passed
			if stepProcessIndex == bean.NullProcessIndex { // if end step, consider it completed and return
				return nil
			}
		}
	}
}

func (impl *ImageScanServiceImpl) ProcessScanStep(step repository.ScanToolStep, tool repository.ScanToolMetadata, toolOutputDirPath string, ctx context.Context, imageScanRenderDto *common.ImageScanRenderDto, proxyUrl string) ([]byte, error) {
	outputFileNameForThisStep := path.Join(toolOutputDirPath, fmt.Sprintf("%d%s", step.Index, bean.JsonOutputFileNameSuffix))
	var output []byte
	if step.StepExecutionType == bean.ScanExecutionTypeHttp {
		queryParams, httpHeaders, inputPayload, err := impl.GetHttpStepInputParams(step, toolOutputDirPath, nil)
		if err != nil {
			impl.Logger.Errorw("error in getting http step input params", "err", err)
			return nil, err
		}
		output, err = httpUtil.HandleHTTPRequest(tool.ServerBaseUrl, step.HttpMethodType, httpHeaders, queryParams, inputPayload, outputFileNameForThisStep, ctx)
		if err != nil {
			impl.Logger.Errorw("error in http request txn", "err", err)
			return nil, err
		}
	} else if step.StepExecutionType == bean.ScanExecutionTypeCli {
		imageScanRenderDto.OutputFilePath = outputFileNameForThisStep
		renderedCommand, err := impl.GetCliInputParams(step, toolOutputDirPath, imageScanRenderDto, tool.ToolMetaData)
		if err != nil {
			impl.Logger.Errorw("error in getting cli step input params", "err", err)
			return nil, err
		}
		proxyEnv := impl.FetchProxyEnvForCliRequest(proxyUrl)
		output, err = cliUtil.HandleCliRequest(renderedCommand, outputFileNameForThisStep, ctx, step.CliOutputType, nil, proxyEnv)
		if err != nil {
			impl.Logger.Errorw("error in cli request txn", "err", err)
			return nil, err
		}
	}
	return output, nil
}

func (impl *ImageScanServiceImpl) ConvertEndStepOutputAndSaveVulnerabilities(stepOutput []byte, executionHistoryId int, tool repository.ScanToolMetadata, step repository.ScanToolStep, userId int32) error {
	//rendering image descriptor template with output json to get vulnerabilities updated
	renderedTemplate, err := commonUtil.ParseJsonTemplate(tool.ResultDescriptorTemplate, stepOutput)
	if err != nil {
		impl.Logger.Errorw("error in parsing template to get vulnerabilities", "err", err)
		return err
	}
	renderedTemplate = common.RemoveTrailingComma(renderedTemplate)
	var vulnerabilities []*bean.ImageScanOutputObject
	err = json.Unmarshal([]byte(renderedTemplate), &vulnerabilities)
	if err != nil {
		impl.Logger.Errorw("error in unmarshalling rendered template", "err", err)
		return err
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
		allSavedCves, err := impl.CveStoreRepository.FindByCveNames(allCvesNames)
		if err != nil {
			if err == pg.ErrNoRows {
				// in case of no cve found , just ignore
				impl.Logger.Infow("no saved cves found", err)
			} else {
				impl.Logger.Errorw("error in getting all cves ", "err", err)
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
	tx, err := impl.CveStoreRepository.GetConnection().Begin()
	if err != nil {
		impl.Logger.Errorw("error in initiating db transaction", "err", err)
		return err
	}
	// Rollback tx on error.
	defer tx.Rollback()
	if len(cvesToBeSaved) > 0 {
		err = impl.CveStoreRepository.SaveInBatch(cvesToBeSaved, tx)
		if err != nil {
			impl.Logger.Errorw("error in saving cves in batch", "err", err)
			return err
		}
	}
	if len(imageScanExecutionResults) > 0 {
		err = impl.ScanResultRepository.SaveInBatch(imageScanExecutionResults, tx)
		if err != nil {
			impl.Logger.Errorw("error in saving scan execution results", "err", err)
			return err
		}
	}
	err = tx.Commit()
	if err != nil {
		impl.Logger.Errorw("error in committing transaction", "err", err)
		return err
	}
	return nil
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
			impl.Logger.Errorw("error in unmarshalling query params", "err", err)
			return queryParams, httpHeaders, inputPayload, err
		}
	}
	if step.HttpReqHeaders != nil {
		err = json.Unmarshal(step.HttpReqHeaders, &httpHeaders)
		if err != nil {
			impl.Logger.Errorw("error in unmarshalling http headers", "err", err)
			return queryParams, httpHeaders, inputPayload, err
		}
	}
	inputPayloadBytes, err = impl.RenderInputDataForAStep(string(step.HttpInputPayload), step.RenderInputDataFromStep, toolOutputDirPath, imageScanRenderDto, "")
	if err != nil {
		impl.Logger.Errorw("error in rendering http input payload", "err", err)
		return queryParams, httpHeaders, inputPayload, err
	}
	inputPayload = bytes.NewBuffer(inputPayloadBytes)
	return queryParams, httpHeaders, inputPayload, nil
}

func (impl *ImageScanServiceImpl) GetCliInputParams(step repository.ScanToolStep, toolOutputDirPath string, imageScanRenderDto *common.ImageScanRenderDto, toolMetaData string) (string, error) {
	var err error
	var renderedCommand []byte
	renderedCommand, err = impl.RenderInputDataForAStep(step.CliCommand, step.RenderInputDataFromStep, toolOutputDirPath, imageScanRenderDto, toolMetaData)
	if err != nil {
		impl.Logger.Errorw("error in rendering cli input args", "err", err)
		return "", err
	}
	return string(renderedCommand), nil
}

func (impl *ImageScanServiceImpl) RenderInputDataForAStep(inputPayloadTmpl string, outputStepIndex int, toolExecutionDirectoryPath string, imageScanRenderDto *common.ImageScanRenderDto, toolMetaData string) ([]byte, error) {
	tmpl := template.Must(template.New("").Parse(inputPayloadTmpl))
	jsonMap := map[string]interface{}{}
	metaDataMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(toolMetaData), &metaDataMap)
	if err != nil {
		impl.Logger.Errorw("error in unmarshalling meta data ", "err", err, "toolMetaData", toolMetaData)
		return nil, err
	}
	if outputStepIndex != bean.NullProcessIndex {
		outputFileName := path.Join(toolExecutionDirectoryPath, fmt.Sprintf("%d%s", outputStepIndex, bean.JsonOutputFileNameSuffix))
		outputFromStep, err := commonUtil.ReadFile(outputFileName)
		if err != nil {
			impl.Logger.Errorw("error in getting reading output of step", "err", err, "stepOutputFileName", outputFromStep)
			return nil, err
		}
		err = json.Unmarshal(outputFromStep, &jsonMap)
		if err != nil {
			impl.Logger.Errorw("error in unmarshalling", "err", err)
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

	for key, val := range metaDataMap {
		jsonMap[key] = val
	}
	buf := &bytes.Buffer{}
	err = tmpl.Execute(buf, jsonMap)
	if err != nil {
		impl.Logger.Errorw("error in executing template", "err", err)
		return nil, err
	}
	return buf.Bytes(), nil
}

func (impl *ImageScanServiceImpl) CreateScanExecutionRegistryForClairV4(vs []*claircore.Vulnerability, event *common.ImageScanEvent, toolId int, executionHistory *repository.ImageScanExecutionHistory) ([]*claircore.Vulnerability, error) {

	var cveNames []string
	for _, item := range vs {
		impl.Logger.Debugw("vulnerability data", "vs", item)
		cveStore, err := impl.CveStoreRepository.FindByName(item.Name)
		if err != nil && err != pg.ErrNoRows {
			impl.Logger.Errorw("Failed to fetch cve", "err", err)
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
			err := impl.CveStoreRepository.Save(cveStore)
			if err != nil {
				impl.Logger.Errorw("Failed to save cve", "err", err)
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
		err := impl.ScanResultRepository.Save(imageScanExecutionResult)
		if err != nil {
			impl.Logger.Errorw("Failed to save cve", "err", err)
			return nil, err
		}
	}
	return vs, nil
}

func (impl *ImageScanServiceImpl) CreateScanExecutionRegistryForClairV2(vs []*clair.Vulnerability, event *common.ImageScanEvent, toolId int, executionHistory *repository.ImageScanExecutionHistory) ([]*clair.Vulnerability, error) {

	var cveNames []string
	for _, item := range vs {
		impl.Logger.Debugw("vulnerability data", "vs", item)
		cveStore, err := impl.CveStoreRepository.FindByName(item.Name)
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
			lowerCaseSeverity := bean.ConvertToLowerCase(item.Severity)
			cveStore.Severity = bean.ConvertToSeverityUtility(lowerCaseSeverity)
			cveStore.StandardSeverity = bean.ConvertToStandardSeverityUtility(lowerCaseSeverity)
			cveStore.CreatedOn = time.Now()
			cveStore.CreatedBy = int32(event.UserId)
			cveStore.UpdatedOn = time.Now()
			cveStore.UpdatedBy = int32(event.UserId)
			err := impl.CveStoreRepository.Save(cveStore)
			if err != nil {
				impl.Logger.Errorw("Failed to save cve", "err", err)
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
		err := impl.ScanResultRepository.Save(imageScanExecutionResult)
		if err != nil {
			impl.Logger.Errorw("Failed to save cve", "err", err)
			return nil, err
		}
	}
	return vs, nil
}

func (impl *ImageScanServiceImpl) IsImageScanned(image string) (bool, error) {
	scanned := false
	scanHistory, err := impl.ScanHistoryRepository.FindByImage(image)
	if err != nil && err != pg.ErrNoRows {
		impl.Logger.Errorw("error in fetching scan history ", "err", err)
		return scanned, err
	}
	scanHistoryId := 0
	if scanHistory != nil {
		scanHistoryId = scanHistory.Id
		//scanned = true
	}
	if scanHistoryId > 0 {
		scanHistoryMappings, err := impl.ScanToolExecutionHistoryMappingRepository.GetAllScanHistoriesByExecutionHistoryIdAndStates(scanHistoryId, []bean.ScanExecutionProcessState{bean.ScanExecutionProcessStateRunning, bean.ScanExecutionProcessStateCompleted})
		if err != nil && err != pg.ErrNoRows {
			impl.Logger.Errorw("error in getting history mappings", "err", err)
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
	conditions, err := impl.ScanStepConditionRepository.FindAllByToolStepId(step.Id)
	if err != nil {
		impl.Logger.Errorw("error in getting all conditions by step id", "err", err, "stepId", step.Id)
		return false, err
	}
	for _, condition := range conditions {
		isPassedForCondition, err := impl.EvaluateCondition(*condition, stepOutput)
		if err != nil {
			impl.Logger.Errorw("error in evaluating condition", "err", err, "condition", condition)
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

func (impl *ImageScanServiceImpl) HandleProgressingScans() {
	//marking all scans failed which have crossed try count
	err := impl.ScanToolExecutionHistoryMappingRepository.MarkAllRunningStateAsFailedHavingTryCountReachedLimit(impl.ImageScanConfig.ScanTryCount)
	if err != nil {
		impl.Logger.Errorw("error in marking all running scan states as failed", "err", err)
		return
	}

	//getting all scans which are in progressing after marking failed
	scanHistories, err := impl.ScanToolExecutionHistoryMappingRepository.GetAllScanHistoriesByState(bean.ScanExecutionProcessStateRunning)
	if err != nil {
		impl.Logger.Errorw("error in getting all scans by running state", "err", err)
		return
	}

	var executionHistoryDirPath string
	flagForDeleting := false
	// Create Folder for output data for execution history only if any pending scans are there due to pod died
	if len(scanHistories) > 0 {
		flagForDeleting = true
		executionHistoryDirPath = impl.CreateFolderForOutputData(scanHistories[0].ImageScanExecutionHistoryId)
	}
	wg := &sync.WaitGroup{}
	wg.Add(len(scanHistories))
	imagescanExecutionHistories, err := impl.ScanHistoryRepository.FindAll()
	if err != nil {
		impl.Logger.Errorw("error in getting scan histories on start up", "err", err)
		return
	}
	imageScanToolMetadatas, err := impl.ScanToolMetadataRepository.FindAllActiveTools()
	if err != nil {
		impl.Logger.Errorw("error in getting all active tools", "err", err)
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
		scanEventJson := imageScanExecutionHistoryMap[scanHistory.ImageScanExecutionHistoryId].ScanEventJson
		if len(scanEventJson) == 0 {
			return
		}
		scanTool := imageScanToolsMap[scanHistory.ScanToolId]
		err = json.Unmarshal([]byte(scanEventJson), &scanHistory)
		if err != nil {
			impl.Logger.Errorw("error in un-marshaling", "err", err)
			return
		}
		imageScanRenderDto, err := impl.GetImageScanRenderDto(scanEvent.DockerRegistryId, scanEvent.Image)
		if err != nil {
			impl.Logger.Errorw("service error, GetImageScanRenderDto", "err", err, "dockerRegistryId", scanEvent.DockerRegistryId)
			return
		}
		proxyUrl := impl.FetchProxyUrl(&scanEvent)
		err = impl.ScanImageForTool(scanTool, scanHistory.ImageScanExecutionHistoryId, executionHistoryDirPath, wg, 1, nil, imageScanRenderDto, proxyUrl)
		if err != nil {
			impl.Logger.Errorw("error in scanning image", "err", err)
			return
		}
	}
	wg.Wait()

	//deleting executionDirectoryPath
	if flagForDeleting {
		err = os.Remove(executionHistoryDirPath)
		if err != nil {
			impl.Logger.Errorw("error in deleting executionHistoryDirectory", "err", err, "executionHistoryDirPath", executionHistoryDirPath)
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
