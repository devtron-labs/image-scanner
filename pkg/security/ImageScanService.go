package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/internal/sql/bean"
	"github.com/devtron-labs/image-scanner/internal/sql/repository"
	cli_util "github.com/devtron-labs/image-scanner/internal/step-lib/util/cli-util"
	common_util "github.com/devtron-labs/image-scanner/internal/step-lib/util/common-util"
	http_util "github.com/devtron-labs/image-scanner/internal/step-lib/util/http-util"
	thread_lib "github.com/devtron-labs/image-scanner/internal/thread-lib"
	"github.com/go-pg/pg"
	"github.com/optiopay/klar/clair"
	"github.com/quay/claircore"
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
	CreateScanExecutionRegistryForClairV4(vs []*claircore.Vulnerability, event *common.ImageScanEvent) ([]*claircore.Vulnerability, error)
	CreateScanExecutionRegistryForClairV2(vs []*clair.Vulnerability, event *common.ImageScanEvent) ([]*clair.Vulnerability, error)
	IsImageScanned(image string) (bool, error)
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
	threadPool                                thread_lib.ThreadPool
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
	threadPool thread_lib.ThreadPool) *ImageScanServiceImpl {
	return &ImageScanServiceImpl{logger: logger, scanHistoryRepository: scanHistoryRepository, scanResultRepository: scanResultRepository,
		scanObjectMetaRepository: scanObjectMetaRepository, cveStoreRepository: cveStoreRepository,
		imageScanDeployInfoRepository:             imageScanDeployInfoRepository,
		ciArtifactRepository:                      ciArtifactRepository,
		scanToolExecutionHistoryMappingRepository: scanToolExecutionHistoryMappingRepository,
		scanToolMetadataRepository:                scanToolMetadataRepository,
		scanStepConditionRepository:               scanStepConditionRepository,
		scanToolStepRepository:                    scanToolStepRepository,
		scanStepConditionMappingRepository:        scanStepConditionMappingRepository,
		threadPool:                                threadPool,
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
	tools, err := impl.scanToolMetadataRepository.FindAllActiveToolsByScanTarget(repository.ImageScanTargetType)
	if err != nil {
		impl.logger.Errorw("error in getting all active tools", "")
		return err
	}
	executionHistory, executionHistoryDirPath, err := impl.RegisterScanExecutionHistoryAndState(scanEvent, tools)
	if err != nil {
		impl.logger.Errorw("service err, RegisterScanExecutionHistoryAndState", "err", err)
		return err
	}
	wg := &sync.WaitGroup{}
	wg.Add(len(tools))
	for _, tool := range tools {
		toolCopy := *tool
		executionHistoryId := executionHistory.Id
		executionHistoryDirPathCopy := executionHistoryDirPath
		impl.threadPool.AddThreadToExecutionQueue(func() {
			var processedState bean.ScanExecutionProcessState
			err = impl.ProcessScanForATool(toolCopy, executionHistoryDirPathCopy)
			if err != nil {
				impl.logger.Errorw("error in processing scan for tool:", toolCopy.Name, "err", err)
				processedState = bean.ScanExecutionProcessStateFailed
			} else {
				processedState = bean.ScanExecutionProcessStateCompleted
			}
			err := impl.scanToolExecutionHistoryMappingRepository.UpdateStateByToolAndExecutionHistoryId(executionHistoryId, toolCopy.Id, processedState, time.Now())
			if err != nil {
				impl.logger.Errorw("error in UpdateStateByToolAndExecutionHistoryId", "err", err)
			}
			wg.Done()
		})
	}
	wg.Wait()
	//TODO : delete executionHistoryDirectory
	return nil
}

func (impl *ImageScanServiceImpl) RegisterScanExecutionHistoryAndState(scanEvent *common.ImageScanEvent,
	tools []*repository.ScanToolMetadata) (*repository.ImageScanExecutionHistory, string, error) {
	executionHistoryDirPath := ""
	//creating execution history
	executionTimeStart := time.Now()
	executionHistoryModel := &repository.ImageScanExecutionHistory{
		Image:         scanEvent.Image,
		ImageHash:     scanEvent.ImageDigest,
		ExecutionTime: executionTimeStart,
		ExecutedBy:    scanEvent.UserId,
	}
	err := impl.scanHistoryRepository.Save(executionHistoryModel)
	if err != nil {
		impl.logger.Errorw("Failed to save executionHistory", "err", err, "model", executionHistoryModel)
		return nil, executionHistoryDirPath, err
	}
	// creating folder for storing output data for this execution history data
	executionHistoryModelIdStr := strconv.Itoa(executionHistoryModel.Id)
	executionHistoryDirPath = path.Join(bean.ScanOutputDirectory, executionHistoryModelIdStr)
	err = os.Mkdir(executionHistoryDirPath, common_util.DefaultFileCreatePermission)
	if err != nil && !os.IsExist(err) {
		impl.logger.Errorw("error in creating executionHistory directory", "err", err, "executionHistoryId", executionHistoryModel.Id)
		return nil, executionHistoryDirPath, err
	}
	executionHistoryMappingModels := make([]*repository.ScanToolExecutionHistoryMapping, len(tools))
	for _, tool := range tools {
		model := &repository.ScanToolExecutionHistoryMapping{
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
		executionHistoryMappingModels = append(executionHistoryMappingModels, model)
	}
	err = impl.scanToolExecutionHistoryMappingRepository.SaveInBatch(executionHistoryMappingModels)
	if err != nil {
		impl.logger.Errorw("Failed to save executionHistoryMappingModels", "err", err)
		return nil, executionHistoryDirPath, err
	}
	return executionHistoryModel, executionHistoryDirPath, nil
}

func (impl *ImageScanServiceImpl) ProcessScanForATool(tool repository.ScanToolMetadata, executionHistoryDirPath string) error {
	// creating folder for storing this tool output data
	toolIdStr := strconv.Itoa(tool.Id)
	toolOutputDirPath := path.Join(executionHistoryDirPath, toolIdStr)
	err := os.Mkdir(toolOutputDirPath, common_util.DefaultFileCreatePermission)
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
			err, isPassed := impl.ProcessScanStep(step, tool, toolOutputDirPath)
			if err != nil {
				impl.logger.Errorw("error in processing scan step sync", "err", err, "stepId", step.Id)
				return err
			}
			if step.ExecuteStepOnPass == bean.NullProcessIndex && isPassed { //step process is passed and scanning is completed
				//TODO: use this steps output to get vulnerabilities
				return nil
			} else if step.ExecuteStepOnFail == bean.NullProcessIndex && !isPassed { //step process is failed and scanning is completed
				return fmt.Errorf("error in executing step with index : %d", stepProcessIndex)
			} else if isPassed { //step process is passed and have to move to next step for processing
				stepProcessIndex = step.ExecuteStepOnPass
			} else if !isPassed { //step process is failed and have to move to next step for processing
				stepProcessIndex = step.ExecuteStepOnFail //this step can be equal to the same step in case of retry or can be other one
			}
		} else { //async type processing
			go func() {
				//will not check if step is passed or failed
				err, _ := impl.ProcessScanStep(step, tool, toolOutputDirPath)
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

func (impl *ImageScanServiceImpl) ProcessScanStep(step repository.ScanToolStep, tool repository.ScanToolMetadata, toolOutputDirPath string) (error, bool) {
	outputFileNameForThisStep := path.Join(toolOutputDirPath, fmt.Sprintf("%d%s", step.Index, bean.JsonOutputFileNameSuffix))
	isPassed := false
	if step.StepExecutionType == bean.ScanExecutionTypeHttp {
		queryParams, httpHeaders, inputPayload, err := impl.GetHttpStepInputParams(step, toolOutputDirPath)
		if err != nil {
			impl.logger.Errorw("error in getting http step input params", "err", err)
			return err, isPassed
		}
		_, err = http_util.HandleHTTPRequest(tool.ServerBaseUrl, step.HttpMethodType, httpHeaders, queryParams, inputPayload, outputFileNameForThisStep)
		if err != nil {
			impl.logger.Errorw("error in http request txn", "err", err)
			return err, isPassed
		}
	} else if step.StepExecutionType == bean.ScanExecutionTypeCli {
		cliArgs, err := impl.GetCliInputParams(step, toolOutputDirPath)
		if err != nil {
			impl.logger.Errorw("error in getting cli step input params", "err", err)
			return err, isPassed
		}
		err = cli_util.HandleCliRequest(tool.BaseCliCommand, outputFileNameForThisStep, context.Background(), step.CliOutputType, cliArgs)
		if err != nil {
			impl.logger.Errorw("error in cli request txn", "err", err)
			return err, isPassed
		}
	}
	return nil, isPassed
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

func (impl *ImageScanServiceImpl) GetCliInputParams(step repository.ScanToolStep, toolOutputDirPath string) (map[string]string, error) {
	var err error
	cliArgs := make(map[string]string)
	inputArgsBytes := step.CliArgs
	if step.RenderInputDataFromStep != bean.NullProcessIndex {
		inputArgsBytes, err = impl.RenderInputDataWithOtherStepOutput(step.CliArgs, step.RenderInputDataFromStep, toolOutputDirPath)
		if err != nil {
			impl.logger.Errorw("error in rendering cli input args", "err", err)
			return cliArgs, err
		}
	}
	if inputArgsBytes != nil {
		err = json.Unmarshal(inputArgsBytes, &cliArgs)
		if err != nil {
			impl.logger.Errorw("error in unmarshalling cli args", "err", err)
			return cliArgs, err
		}
	}
	return cliArgs, nil
}
func (impl *ImageScanServiceImpl) RenderInputDataWithOtherStepOutput(inputPayloadTmpl json.RawMessage, outputStepIndex int, toolExecutionDirectoryPath string) ([]byte, error) {
	tmpl := template.Must(template.New("").Parse(string(inputPayloadTmpl)))
	outputFileName := path.Join(toolExecutionDirectoryPath, fmt.Sprintf("%d%s", outputStepIndex, bean.JsonOutputFileNameSuffix))
	outputFromStep, err := common_util.ReadFile(outputFileName)
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
