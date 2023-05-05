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
	"html/template"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"sync"
	"time"
)

type ImageScanService interface {
	ScanImage(scanEvent *common.ImageScanEvent) error
	CreateScanExecutionRegistryForClairV4(vs []*claircore.Vulnerability, event *common.ImageScanEvent, toolId int) ([]*claircore.Vulnerability, error)
	CreateScanExecutionRegistryForClairV2(vs []*clair.Vulnerability, event *common.ImageScanEvent, toolId int) ([]*clair.Vulnerability, error)
	IsImageScanned(image string) (bool, error)
	ScanImageForTool(tool *repository.ScanToolMetadata, executionHistoryId int, executionHistoryDirPathCopy string, wg *sync.WaitGroup, userId int32, ctx context.Context)
	CreateFolderForOutputData(executionHistoryModelId int) string
	HandleProgressingScans()
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
	imageScanConfig *ImageScanConfig) *ImageScanServiceImpl {
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
	}
	imageScanService.HandleProgressingScans()
	return imageScanService
}

func (impl *ImageScanServiceImpl) ScanImage(scanEvent *common.ImageScanEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(impl.imageScanConfig.ScanImageTimeout)*time.Minute)
	defer cancel()
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
	tool, err := impl.scanToolMetadataRepository.FindActiveToolByScanTarget(repository.ImageScanTargetType)
	if err != nil {
		impl.logger.Errorw("error in getting all active tools", "")
		return err
	}
	executionHistory, executionHistoryDirPath, err := impl.RegisterScanExecutionHistoryAndState(scanEvent, tool)
	if err != nil {
		impl.logger.Errorw("service err, RegisterScanExecutionHistoryAndState", "err", err)
		return err
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	impl.ScanImageForTool(tool, executionHistory.Id, executionHistoryDirPath, wg, int32(scanEvent.UserId), ctx)
	wg.Wait()
	//deleting executionDirectoryPath
	err = os.Remove(executionHistoryDirPath)
	if err != nil {
		impl.logger.Errorw("error in deleting executionHistoryDirectory", "err", err)
		return err
	}
	return nil
}
func (impl *ImageScanServiceImpl) ScanImageForTool(tool *repository.ScanToolMetadata, executionHistoryId int, executionHistoryDirPathCopy string, wg *sync.WaitGroup, userId int32, ctx context.Context) {
	toolCopy := *tool
	var processedState bean.ScanExecutionProcessState
	err := impl.ProcessScanForTool(toolCopy, executionHistoryDirPathCopy, executionHistoryId, userId, ctx)
	if err != nil {
		impl.logger.Errorw("error in processing scan for tool:", toolCopy.Name, "err", err)
		processedState = bean.ScanExecutionProcessStateFailed
	} else {
		processedState = bean.ScanExecutionProcessStateCompleted
	}
	err = impl.scanToolExecutionHistoryMappingRepository.UpdateStateByToolAndExecutionHistoryId(executionHistoryId, toolCopy.Id, processedState, time.Now())
	if err != nil {
		impl.logger.Errorw("error in UpdateStateByToolAndExecutionHistoryId", "err", err)
	}
	wg.Done()
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
		impl.logger.Errorw("error in marshalling scanEvent", "err", err, "event", scanEvent)
		return nil, "", err
	}
	executionHistoryModel := &repository.ImageScanExecutionHistory{
		Image:         scanEvent.Image,
		ImageHash:     scanEvent.ImageDigest,
		ExecutionTime: executionTimeStart,
		ExecutedBy:    scanEvent.UserId,
		ScanEventJson: string(scanEventJson),
	}
	err = impl.scanHistoryRepository.Save(executionHistoryModel)
	if err != nil {
		impl.logger.Errorw("Failed to save executionHistory", "err", err, "model", executionHistoryModel)
		return nil, executionHistoryDirPath, err
	}
	// creating folder for storing output data for this execution history data
	executionHistoryDirPath = impl.CreateFolderForOutputData(executionHistoryModel.Id)
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

func (impl *ImageScanServiceImpl) ProcessScanForTool(tool repository.ScanToolMetadata, executionHistoryDirPath string, executionHistoryId int, userId int32, ctx context.Context) error {
	imageScanConfig := &ImageScanConfig{}
	err := env.Parse(imageScanConfig)
	if err != nil {
		impl.logger.Errorw("error in parsing env ", "err", err)
		return err
	}
	// creating folder for storing this tool output data
	toolIdStr := strconv.Itoa(tool.Id)
	toolOutputDirPath := path.Join(executionHistoryDirPath, toolIdStr)
	err = os.Mkdir(toolOutputDirPath, commonUtil.DefaultFileCreatePermission)
	if err != nil && !os.IsExist(err) {
		impl.logger.Errorw("error in creating toolOutput directory", "err", err, "toolId", tool.Id, "executionHistoryDir", executionHistoryDirPath)
		return err
	}
	//getting all steps for this tool
	steps, err := impl.scanToolStepRepository.FindAllByScanToolId(tool.Id)
	if err != nil {
		impl.logger.Errorw("error in getting steps by scan tool id", "err", err, "toolId", tool.Id)
		return err
	}
	//sorting steps on the basis of index
	sort.Slice(steps, func(i, j int) bool { return steps[i].Index < steps[j].Index })
	stepIndexMap := make(map[int]repository.ScanToolStep)
	stepTryCount := make(map[int]int) //map of stepIndex and it's try count
	var stepProcessIndex int
	//setting index of first step for processing starting point
	stepProcessIndex = steps[0].Index
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
			output, err := impl.ProcessScanStep(step, tool, toolOutputDirPath, ctx)
			if err != nil {
				impl.logger.Errorw("error in processing scan step sync", "err", err, "stepId", step.Id)
				return err
			}
			if step.StepExecutionType == bean.ScanExecutionTypeCli && step.CliOutputType == cliUtil.CliOutPutTypeStream {
				// read output here for further processing, to update this logic when cli stream processing is made async
				outputFileName := path.Join(toolOutputDirPath, fmt.Sprintf("%d%s", step.Index, bean.JsonOutputFileNameSuffix))
				output, err = commonUtil.ReadFile(outputFileName)
				if err != nil {
					impl.logger.Errorw("error in getting reading output of step", "err", err, "stepOutputFileName", outputFileName)
					return err
				}
			}
			if !gjson.Valid(string(output)) {
				return errors.New("invalid json output, exiting")
			}

			isPassed, err := impl.CheckConditionsForAStep(step, output)
			if err != nil {
				impl.logger.Errorw("error in checking conditions for step", "err", err, "stepId", step.Id)
				return err
			}
			if !isPassed {
				impl.logger.Infow("conditions not passed for step", "stepId", step.Id)
				return fmt.Errorf("conditions not passed for step with index : %d", step.Index)
			}
			if step.ExecuteStepOnPass == bean.NullProcessIndex && isPassed { //step process is passed and scanning is completed
				err = impl.ConvertEndStepOutputAndSaveVulnerabilities(output, executionHistoryId, tool, step, userId)
				if err != nil {
					impl.logger.Errorw("error in saving vulnerabilities", "err", err)
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
				_, err := impl.ProcessScanStep(step, tool, toolOutputDirPath, cxtx)
				if err != nil {
					impl.logger.Errorw("error in processing scan step async", "err", err, "stepId", step.Id)
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

func (impl *ImageScanServiceImpl) ProcessScanStep(step repository.ScanToolStep, tool repository.ScanToolMetadata, toolOutputDirPath string, ctx context.Context) ([]byte, error) {
	outputFileNameForThisStep := path.Join(toolOutputDirPath, fmt.Sprintf("%d%s", step.Index, bean.JsonOutputFileNameSuffix))
	var output []byte
	if step.StepExecutionType == bean.ScanExecutionTypeHttp {
		queryParams, httpHeaders, inputPayload, err := impl.GetHttpStepInputParams(step, toolOutputDirPath)
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
		cliArgs, err := impl.GetCliInputParams(step, toolOutputDirPath)
		if err != nil {
			impl.logger.Errorw("error in getting cli step input params", "err", err)
			return nil, err
		}
		output, err = cliUtil.HandleCliRequest(tool.BaseCliCommand, outputFileNameForThisStep, ctx, step.CliOutputType, cliArgs)
		if err != nil {
			impl.logger.Errorw("error in cli request txn", "err", err)
			return nil, err
		}
	}
	return output, nil
}

func (impl *ImageScanServiceImpl) ConvertEndStepOutputAndSaveVulnerabilities(stepOutput []byte, executionHistoryId int, tool repository.ScanToolMetadata, step repository.ScanToolStep, userId int32) error {
	//rendering image descriptor template with output json to get vulnerabilities updated
	renderedTemplate, err := commonUtil.ParseJsonTemplate(tool.ResultDescriptorTemplate, stepOutput)
	if err != nil {
		impl.logger.Errorw("error in parsing template to get vulnerabilities", "err", err)
		return err
	}
	var vulnerabilities []*bean.ImageScanOutputObject
	err = json.Unmarshal([]byte(renderedTemplate), &vulnerabilities)
	if err != nil {
		impl.logger.Errorw("error in unmarshalling rendered template", "err", err)
		return err
	}
	allCves := make([]*repository.CveStore, 0, len(vulnerabilities))
	cvesToBeSaved := make([]*repository.CveStore, 0, len(vulnerabilities))
	for _, vul := range vulnerabilities {
		cve, err := impl.cveStoreRepository.FindByName(vul.Name)
		if err != nil && err != pg.ErrNoRows {
			impl.logger.Errorw("error in getting cve by name", "err", err, "name", vul.Name)
			return err
		}
		if len(cve.Name) == 0 {
			cve = &repository.CveStore{
				Name:         vul.Name,
				Package:      vul.Package,
				Version:      vul.PackageVersion,
				FixedVersion: vul.FixedInVersion,
			}
			cve.Severity = bean.ConvertToSeverity[vul.Severity]
			cve.CreatedOn = time.Now()
			cve.CreatedBy = userId
			cve.UpdatedOn = time.Now()
			cve.UpdatedBy = userId
			cvesToBeSaved = append(cvesToBeSaved, cve)
		}
		allCves = append(allCves, cve)
	}

	imageScanExecutionResults := make([]*repository.ImageScanExecutionResult, 0, len(allCves))
	for _, cve := range allCves {
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

func (impl *ImageScanServiceImpl) GetHttpStepInputParams(step repository.ScanToolStep, toolOutputDirPath string) (url.Values, map[string]string, *bytes.Buffer, error) {
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
	if step.RenderInputDataFromStep != bean.NullProcessIndex {
		inputPayloadBytes, err = impl.RenderInputDataWithOtherStepOutput(step.HttpInputPayload, step.RenderInputDataFromStep, toolOutputDirPath)
		if err != nil {
			impl.logger.Errorw("error in rendering http input payload", "err", err)
			return queryParams, httpHeaders, inputPayload, err
		}
	}
	inputPayload = bytes.NewBuffer(inputPayloadBytes)
	return queryParams, httpHeaders, inputPayload, nil
}

func (impl *ImageScanServiceImpl) GetCliInputParams(step repository.ScanToolStep, toolOutputDirPath string) (string, error) {
	var err error
	var renderedCommand []byte
	if step.RenderInputDataFromStep != bean.NullProcessIndex {
		renderedCommand, err = impl.RenderInputDataWithOtherStepOutput(step.CliCommand, step.RenderInputDataFromStep, toolOutputDirPath)
		if err != nil {
			impl.logger.Errorw("error in rendering cli input args", "err", err)
			return "", err
		}
	}
	return string(renderedCommand), nil
}

func (impl *ImageScanServiceImpl) RenderInputDataWithOtherStepOutput(inputPayloadTmpl string, outputStepIndex int, toolExecutionDirectoryPath string) ([]byte, error) {
	tmpl := template.Must(template.New("").Parse(inputPayloadTmpl))
	outputFileName := path.Join(toolExecutionDirectoryPath, fmt.Sprintf("%d%s", outputStepIndex, bean.JsonOutputFileNameSuffix))
	outputFromStep, err := commonUtil.ReadFile(outputFileName)
	if err != nil {
		impl.logger.Errorw("error in getting reading output of step", "err", err, "stepOutputFileName", outputFromStep)
		return nil, err
	}
	jsonMap := map[string]interface{}{}
	err = json.Unmarshal(outputFromStep, &jsonMap)
	if err != nil {
		impl.logger.Errorw("error in unmarshalling", "err", err)
		return nil, err
	}
	buf := &bytes.Buffer{}
	err = tmpl.Execute(buf, jsonMap)
	if err != nil {
		impl.logger.Errorw("error in executing template", "err", err)
		return nil, err
	}
	return buf.Bytes(), nil
}

func (impl *ImageScanServiceImpl) CreateScanExecutionRegistryForClairV4(vs []*claircore.Vulnerability, event *common.ImageScanEvent, toolId int) ([]*claircore.Vulnerability, error) {

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

func (impl *ImageScanServiceImpl) CreateScanExecutionRegistryForClairV2(vs []*clair.Vulnerability, event *common.ImageScanEvent, toolId int) ([]*clair.Vulnerability, error) {

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
	if scanHistory != nil && scanHistory.Id > 0 {
		scanned = true
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

func (impl *ImageScanServiceImpl) HandleProgressingScans() {
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
	// Create Folder for output data for execution history only if any pending scans are there due to pod died
	if len(scanHistories) > 0 {
		executionHistoryDirPath = impl.CreateFolderForOutputData(scanHistories[0].ImageScanExecutionHistoryId)
	}
	wg := &sync.WaitGroup{}
	wg.Add(len(scanHistories))
	// System doing image scanning for all pending scans
	for _, scanHistory := range scanHistories {
		impl.ScanImageForTool(&scanHistory.ScanToolMetadata, scanHistory.ImageScanExecutionHistoryId, executionHistoryDirPath, wg, 1, nil)

	}
	wg.Wait()
	//deleting executionDirectoryPath
	err = os.Remove(executionHistoryDirPath)
	if err != nil {
		impl.logger.Errorw("error in deleting executionHistoryDirectory", "err", err)
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
	ScanImageTimeout      int    `env:"IMAGE_SCAN_TIMEOUT" envDefault:"5"`
	ScanImageAsyncTimeout int    `env:"IMAGE_SCAN_ASYNC_TIMEOUT" envDefault:"3"`
}
