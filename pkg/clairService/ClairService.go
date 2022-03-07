package clairService

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/caarlos0/env"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/internal/sql/repository"
	"github.com/devtron-labs/image-scanner/pkg/security"
	"github.com/go-pg/pg"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/quay/claircore"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
)

type ClairConfig struct {
	ClairAddress string `env:"CLAIR_ADDR" envDefault:"http://localhost:6060"`
}

type ClairService interface {
	ScanImage(scanEvent *common.ScanEvent) (*common.ScanEventResponse, error)
	CheckIfIndexReportExistsForManifestHash(manifestHash claircore.Digest) (bool, error)
	CreateIndexReportFromManifest(manifest *claircore.Manifest) error
	GetVulnerabilityReportFromManifestHash(manifestHash claircore.Digest) (*claircore.VulnerabilityReport, error)
	DeleteIndexReportFromManifestHash(manifestHash claircore.Digest) error
}
type ClairServiceImpl struct {
	logger                        *zap.SugaredLogger
	clairConfig                   *ClairConfig
	httpClient                    *http.Client
	imageScanService              security.ImageScanService
	dockerArtifactStoreRepository repository.DockerArtifactStoreRepository
}

func NewClairServiceImpl(logger *zap.SugaredLogger, clairConfig *ClairConfig,
	httpClient *http.Client, imageScanService security.ImageScanService,
	dockerArtifactStoreRepository repository.DockerArtifactStoreRepository) *ClairServiceImpl {
	return &ClairServiceImpl{
		logger:                        logger,
		clairConfig:                   clairConfig,
		httpClient:                    httpClient,
		imageScanService:              imageScanService,
		dockerArtifactStoreRepository: dockerArtifactStoreRepository,
	}
}

func GetClairConfig() (*ClairConfig, error) {
	cfg := &ClairConfig{}
	err := env.Parse(cfg)
	if err != nil {
		return nil, errors.New("could not get clair config from environment")
	}
	return cfg, err
}

func (impl *ClairServiceImpl) ScanImage(scanEvent *common.ScanEvent) (*common.ScanEventResponse, error) {
	impl.logger.Debugw("new request, scan image", "requestPayload", scanEvent)
	scanEventResponse := &common.ScanEventResponse{
		RequestData: scanEvent,
	}
	isImageScanned, err := impl.imageScanService.IsImageScanned(scanEvent.Image)
	if err != nil && err != pg.ErrNoRows {
		impl.logger.Errorw("error in fetching scan history ", "err", err, "image", scanEvent.Image)
		return nil, err
	}
	if isImageScanned {
		impl.logger.Infow("image already scanned, skipping further process", "image", scanEvent.Image)
		return scanEventResponse, nil
	}

	//get manifest from image
	manifest, err := impl.CreateClairManifest(scanEvent)
	if err != nil {
		impl.logger.Errorw("error in creating clair manifest", "err", err, "scanEvent", scanEvent)
		return nil, err
	}
	//end get manifest

	//checking if index report exists for this manifest hash; if it does, no need of creating index report
	exists, err := impl.CheckIfIndexReportExistsForManifestHash(manifest.Hash)
	if err != nil {
		impl.logger.Infow("err in checking if index report exists, trying once again", "err", err, "manifestHash", manifest.Hash)
		exists, err := impl.CheckIfIndexReportExistsForManifestHash(manifest.Hash)
		if !exists {
			impl.logger.Infow("could not check if index report exists in second try", "err", err, "manifestHash", manifest.Hash)
			err = impl.CreateIndexReportFromManifest(manifest)
			if err != nil {
				impl.logger.Errorw("error in creating clair index report", "err", err, "manifest", manifest)
				return nil, err
			}
		}
	} else if !exists {
		//index report do not exist, creating index report for manifest
		err = impl.CreateIndexReportFromManifest(manifest)
		if err != nil {
			impl.logger.Errorw("error in creating clair index report", "err", err, "manifest", manifest)
			return nil, err
		}
	}

	//index report created, now getting vulnerability report
	vulnerabilityReport, err := impl.GetVulnerabilityReportFromManifestHash(manifest.Hash)
	if err != nil {
		impl.logger.Errorw("error in getting vulnerability report by manifest hash", "err", err, "manifestHash", manifest.Hash)
		return nil, err
	}

	//trying to delete index report for manifest hash, if unsuccessful will log and skip
	err = impl.DeleteIndexReportFromManifestHash(manifest.Hash)
	if err != nil {
		impl.logger.Warnw("error in deleting index report from manifest hash", "err", err, "manifestHash", manifest.Hash)
	}
	var vulnerabilities []*claircore.Vulnerability
	for _, vulnerability := range vulnerabilityReport.Vulnerabilities {
		vulnerabilities = append(vulnerabilities, vulnerability)
	}

	_, err = impl.imageScanService.CreateScanExecutionRegistry(vulnerabilities, scanEvent)
	if err != nil {
		impl.logger.Errorw("error in CreateScanExecutionRegistry", "err", err)
		return scanEventResponse, err
	}
	scanEventResponse.ResponseData = vulnerabilities
	return scanEventResponse, nil
}

func (impl *ClairServiceImpl) CreateClairManifest(scanEvent *common.ScanEvent) (*claircore.Manifest, error) {
	dockerRegistry, err := impl.dockerArtifactStoreRepository.FindById(scanEvent.DockerRegistryId)
	if err != nil {
		impl.logger.Errorw("error in getting docker registry by id", "err", err, "id", scanEvent.DockerRegistryId)
		return nil, err
	}
	var manifest *claircore.Manifest
	reference, err := name.ParseReference(scanEvent.Image, name.WithDefaultRegistry(dockerRegistry.RegistryURL))
	if err != nil {
		impl.logger.Errorw("error in parsing reference of image", "err", err, "image", scanEvent.Image, "registryUrl", dockerRegistry.RegistryURL)
		return nil, err
	}
	//TODO: update auth config fields
	authConfig := authn.AuthConfig{}
	descriptor, err := remote.Get(reference, remote.WithAuth(authn.FromConfig(authConfig)))
	if err != nil {
		impl.logger.Errorw("error in getting image descriptor for given reference", "err", err, "reference", reference)
		return nil, err
	}
	image, err := descriptor.Image()
	if err != nil {
		impl.logger.Errorw("error in getting image by descriptor", "err", err, "descriptor", descriptor)
		return nil, err
	}
	imageDigest, err := image.Digest()
	if err != nil {
		impl.logger.Errorw("error in getting imageDigest by image", "err", err, "image", image)
		return nil, err
	}
	parsedImageDigest, err := claircore.ParseDigest(imageDigest.String())
	if err != nil {
		impl.logger.Errorw("error in getting parsing imageDigest", "err", err, "imageDigest", imageDigest)
		return nil, err
	}
	impl.logger.Debugw("got hash for clair manifest", "hash", parsedImageDigest)
	manifest.Hash = parsedImageDigest

	layers, err := image.Layers()
	if err != nil {
		impl.logger.Errorw("error in getting layers from image", "err", err, "image", image)
		return nil, err
	}
	impl.logger.Debugw("got image layers", "layers", layers, "image", image)

	//getting repository from reference
	repository := reference.Context()
	repositoryURL := url.URL{
		Scheme: repository.Scheme(),
		Host:   repository.RegistryStr(),
	}
	for _, layer := range layers {
		layerDigest, err := layer.Digest()
		if err != nil {
			impl.logger.Errorw("error in getting image digest", "err", err, "image", image)
			return nil, err
		}
		parsedLayerDigest, err := claircore.ParseDigest(layerDigest.String())
		if err != nil {
			impl.logger.Errorw("error in parsing layerDigest", "err", err, "layerDigest", layerDigest)
			return nil, err
		}
		parsedRepositoryUrl, err := repositoryURL.Parse(path.Join("/", "v2", strings.TrimPrefix(repository.RepositoryStr(), repository.RegistryStr()), "blobs", layerDigest.String()))
		if err != nil {
			impl.logger.Errorw("error in parsing repositoryUrl", "err", err, "repositoryUrl", repositoryURL)
			return nil, err
		}
		httpRequest, err := http.NewRequest(http.MethodGet, parsedRepositoryUrl.String(), nil)
		if err != nil {
			impl.logger.Errorw("error in creating new http request", "err", err, "method", http.MethodGet, "url", parsedRepositoryUrl.String())
			return nil, err
		}
		httpRequest.Header.Add("Range", "bytes=0-0")
		httpResponse, err := impl.httpClient.Do(httpRequest)
		if err != nil {
			impl.logger.Errorw("error in sending http request", "err", err, "httpRequest", httpRequest)
			return nil, err
		}
		err = httpResponse.Body.Close()
		if err != nil {
			impl.logger.Errorw("error in closing http request", "err", err)
		}
		httpResponse.Request.Header.Del("User-Agent")
		httpResponse.Request.Header.Del("Range")
		manifest.Layers = append(manifest.Layers, &claircore.Layer{
			Hash:    parsedLayerDigest,
			URI:     httpResponse.Request.URL.String(),
			Headers: httpResponse.Request.Header,
		})
	}
	return manifest, nil
}

func (impl *ClairServiceImpl) CheckIfIndexReportExistsForManifestHash(manifestHash claircore.Digest) (bool, error) {
	impl.logger.Debugw("new request, check if index report exists for manifest hash", "manifestHash", manifestHash)

	//url - base url + "/indexer/api/v1/index_report/{manifest_hash}"
	checkIndexReportUrl := path.Join(impl.clairConfig.ClairAddress, "/indexer/api/v1/index_report", manifestHash.String())
	request, err := http.NewRequest(http.MethodGet, checkIndexReportUrl, nil)
	if err != nil {
		impl.logger.Errorw("error in creating new http request", "err", err, "requestUrl", checkIndexReportUrl)
		return false, err
	}
	response, err := impl.httpClient.Do(request)
	if err != nil {
		impl.logger.Errorw("error in http request - CheckIfIndexReportExistsForManifestHash", "err", err, "manifestHash", manifestHash)
		return false, err
	}
	status := response.StatusCode
	if !(status >= 200 && status <= 299) {
		impl.logger.Infow("index report does not exists for given manifest hash", "responseStatusCode", response.StatusCode, "manifestHash", manifestHash)
		return false, nil
	}
	impl.logger.Debugw("received response - index report exists for given manifest hash", "manifestHash", manifestHash)
	return true, nil
}

func (impl *ClairServiceImpl) CreateIndexReportFromManifest(manifest *claircore.Manifest) error {
	impl.logger.Debugw("new request, create index report from manifest", "manifest", manifest)
	requestBody, err := json.Marshal(manifest)
	if err != nil {
		impl.logger.Errorw("error while marshaling request manifest", "err", err)
		return err
	}
	getIndexReportUrl := path.Join(impl.clairConfig.ClairAddress, "/indexer/api/v1/index_report")
	request, err := http.NewRequest(http.MethodPost, getIndexReportUrl, bytes.NewBuffer(requestBody))
	if err != nil {
		impl.logger.Errorw("error in creating new http request", "err", err, "requestUrl", getIndexReportUrl, "requestBody", requestBody)
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	indexReport, err := impl.httpClient.Do(request)
	if err != nil {
		impl.logger.Errorw("error in http request - CreateIndexReportFromManifest", "err", err, "manifest", manifest)
		return err
	}
	impl.logger.Debugw("created new index report from manifest", "indexReport", indexReport)
	return nil
}

func (impl *ClairServiceImpl) GetVulnerabilityReportFromManifestHash(manifestHash claircore.Digest) (*claircore.VulnerabilityReport, error) {
	impl.logger.Debugw("new request, get vulnerability report from manifest hash", "manifestHash", manifestHash)

	//url - base url + "/matcher/api/v1/vulnerability_report/{manifest_hash}"
	getVulnerabilityReportUrl := path.Join(impl.clairConfig.ClairAddress, "/matcher/api/v1/vulnerability_report", manifestHash.String())
	request, err := http.NewRequest(http.MethodGet, getVulnerabilityReportUrl, nil)
	if err != nil {
		impl.logger.Errorw("error in creating new http request", "err", err, "requestUrl", getVulnerabilityReportUrl)
		return nil, err
	}
	response, err := impl.httpClient.Do(request)
	if err != nil {
		impl.logger.Errorw("error in http request - GetVulnerabilityReportFromManifestHash", "err", err, "manifestHash", manifestHash)
		return nil, err
	}

	status := response.StatusCode
	var vulnerabilityReport *claircore.VulnerabilityReport
	if status >= 200 && status <= 299 {
		responseBody, err := ioutil.ReadAll(response.Body)
		if err != nil {
			impl.logger.Errorw("error in reading http response body - GetVulnerabilityReportFromManifestHash", "err", err)
			return nil, err
		}
		err = json.Unmarshal(responseBody, vulnerabilityReport)
		if err != nil {
			impl.logger.Errorw("error in un-marshaling vulnerability report", "err", err, "responseBody", responseBody)
			return nil, err
		}
	} else {
		impl.logger.Errorw("http request did not succeed", "response", response)
		return nil, fmt.Errorf("http request did not succeed, code: %d", status)
	}

	impl.logger.Debugw("got vulnerability report from manifest hash", "vulnerabilityReport", vulnerabilityReport)
	return vulnerabilityReport, nil
}

func (impl *ClairServiceImpl) DeleteIndexReportFromManifestHash(manifestHash claircore.Digest) error {
	impl.logger.Debugw("new request, delete index report from manifest hash", "manifestHash", manifestHash)

	//url - base url + "/indexer/api/v1/index_report/{manifest_hash}"
	deleteIndexReportUrl := path.Join(impl.clairConfig.ClairAddress, "/indexer/api/v1/index_report", manifestHash.String())
	request, err := http.NewRequest(http.MethodDelete, deleteIndexReportUrl, nil)
	if err != nil {
		impl.logger.Errorw("error in creating new http request", "err", err, "requestUrl", deleteIndexReportUrl)
		return err
	}
	_, err = impl.httpClient.Do(request)
	if err != nil {
		impl.logger.Errorw("error in http request - DeleteIndexReportFromManifestHash", "err", err, "manifestHash", manifestHash)
		return err
	}
	impl.logger.Debugw("deleted index report from manifest hash", "manifestHash", manifestHash)
	return nil
}