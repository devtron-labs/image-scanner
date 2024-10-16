/*
 * Copyright (c) 2024. Devtron Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package clairService

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/caarlos0/env/v6"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/pkg/roundTripper"
	"github.com/devtron-labs/image-scanner/pkg/security"
	"github.com/devtron-labs/image-scanner/pkg/sql/repository"
	"github.com/go-pg/pg"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
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

const (
	CLAIR_INDEX_REPORT_URL         = "/indexer/api/v1/index_report"
	CLAIR_VULNERABILITY_REPORT_URL = "/matcher/api/v1/vulnerability_report"
)

type ClairService interface {
	ScanImage(scanEvent *common.ImageScanEvent, tool *repository.ScanToolMetadata, executionHistory *repository.ImageScanExecutionHistory) (*common.ScanEventResponse, error)
	CheckIfIndexReportExistsForManifestHash(manifestHash claircore.Digest) (bool, error)
	CreateIndexReportFromManifest(manifest *claircore.Manifest) error
	GetVulnerabilityReportFromManifestHash(manifestHash claircore.Digest) (*claircore.VulnerabilityReport, error)
	DeleteIndexReportFromManifestHash(manifestHash claircore.Digest) error
}
type ClairServiceImpl struct {
	Logger                        *zap.SugaredLogger
	ClairConfig                   *ClairConfig
	HttpClient                    *http.Client
	ImageScanService              security.ImageScanService
	DockerArtifactStoreRepository repository.DockerArtifactStoreRepository
	ScanToolMetadataRepository    repository.ScanToolMetadataRepository
	RoundTripperService           roundTripper.RoundTripperService
}

func NewClairServiceImpl(logger *zap.SugaredLogger, clairConfig *ClairConfig,
	httpClient *http.Client, imageScanService security.ImageScanService,
	dockerArtifactStoreRepository repository.DockerArtifactStoreRepository,
	scanToolMetadataRepository repository.ScanToolMetadataRepository, roundTripperService roundTripper.RoundTripperService) *ClairServiceImpl {
	return &ClairServiceImpl{
		Logger:                        logger,
		ClairConfig:                   clairConfig,
		HttpClient:                    httpClient,
		ImageScanService:              imageScanService,
		DockerArtifactStoreRepository: dockerArtifactStoreRepository,
		ScanToolMetadataRepository:    scanToolMetadataRepository,
		RoundTripperService:           roundTripperService,
	}
}

// below code is used from clairctl (changed auth method according to our need) : https://github.com/quay/clair/blob/v4.3.6/cmd/clairctl/client.go#L32

const (
	userAgent = `clairctl/1`
)

// clairctl code ends

func GetClairConfig() (*ClairConfig, error) {
	cfg := &ClairConfig{}
	err := env.Parse(cfg)
	if err != nil {
		return nil, errors.New("could not get clair config from environment")
	}
	if !strings.HasPrefix(cfg.ClairAddress, "http://") && !strings.HasPrefix(cfg.ClairAddress, "https://") {
		cfg.ClairAddress = fmt.Sprintf("http://%s", cfg.ClairAddress)
	}
	return cfg, err
}

func (impl *ClairServiceImpl) ScanImage(scanEvent *common.ImageScanEvent, tool *repository.ScanToolMetadata, executionHistory *repository.ImageScanExecutionHistory) (*common.ScanEventResponse, error) {
	impl.Logger.Debugw("new request, scan image", "requestPayload", scanEvent)
	scanEventResponse := &common.ScanEventResponse{
		RequestData: scanEvent,
	}
	_, isImageScanned, err := impl.ImageScanService.IsImageScanned(scanEvent.Image, false)
	if err != nil && err != pg.ErrNoRows {
		impl.Logger.Errorw("error in fetching scan history ", "err", err, "image", scanEvent.Image)
		return nil, err
	}
	if isImageScanned {
		impl.Logger.Infow("image already scanned, skipping further process", "image", scanEvent.Image)
		return scanEventResponse, nil
	}

	vulnerabilityReport, err := impl.GetVulnerabilityReportFromClair(scanEvent)
	if err != nil {
		impl.Logger.Errorw("error in getting vulnerability report from clair", "err", err, "scanEvent", scanEvent)
		return nil, err
	}

	var vulnerabilities []*claircore.Vulnerability
	for _, vulnerability := range vulnerabilityReport.Vulnerabilities {
		vulnerabilities = append(vulnerabilities, vulnerability)
	}
	_, err = impl.ImageScanService.CreateScanExecutionRegistryForClairV4(vulnerabilities, scanEvent, tool.Id, executionHistory)
	if err != nil {
		impl.Logger.Errorw("error in CreateScanExecutionRegistry", "err", err)
		return scanEventResponse, err
	}
	scanEventResponse.ResponseDataClairV4 = vulnerabilities
	return scanEventResponse, nil
}

func (impl *ClairServiceImpl) GetVulnerabilityReportFromClair(scanEvent *common.ImageScanEvent) (*claircore.VulnerabilityReport, error) {
	//get manifest from image
	manifest, err := impl.CreateClairManifest(scanEvent)
	if err != nil {
		impl.Logger.Errorw("error in creating clair manifest", "err", err, "scanEvent", scanEvent)
		return nil, err
	}
	//end get manifest

	//checking if index report exists for this manifest hash; if it does, no need of creating index report
	exists, err := impl.CheckIfIndexReportExistsForManifestHash(manifest.Hash)
	if err != nil {
		impl.Logger.Infow("err in checking if index report exists, trying once again", "err", err, "manifestHash", manifest.Hash)
		exists, err := impl.CheckIfIndexReportExistsForManifestHash(manifest.Hash)
		if !exists {
			impl.Logger.Infow("could not check if index report exists in second try", "err", err, "manifestHash", manifest.Hash)
			err = impl.CreateIndexReportFromManifest(manifest)
			if err != nil {
				impl.Logger.Errorw("error in creating clair index report", "err", err, "manifest", manifest)
				return nil, err
			}
		}
	} else if !exists {
		//index report do not exist, creating index report for manifest
		err = impl.CreateIndexReportFromManifest(manifest)
		if err != nil {
			impl.Logger.Errorw("error in creating clair index report", "err", err, "manifest", manifest)
			return nil, err
		}
	}

	//index report created, now getting vulnerability report
	vulnerabilityReport, err := impl.GetVulnerabilityReportFromManifestHash(manifest.Hash)
	if err != nil {
		impl.Logger.Errorw("error in getting vulnerability report by manifest hash", "err", err, "manifestHash", manifest.Hash)
		return nil, err
	}

	//trying to delete index report for manifest hash, if unsuccessful will log and skip
	err = impl.DeleteIndexReportFromManifestHash(manifest.Hash)
	if err != nil {
		impl.Logger.Warnw("error in deleting index report from manifest hash", "err", err, "manifestHash", manifest.Hash)
	}
	return vulnerabilityReport, nil
}

func (impl *ClairServiceImpl) CreateClairManifest(scanEvent *common.ImageScanEvent) (*claircore.Manifest, error) {
	roundTripper, err := impl.RoundTripperService.GetRoundTripper(scanEvent)
	if err != nil {
		impl.Logger.Errorw("error in getting round tripper", "err", "image", scanEvent.Image)
		return nil, err
	}
	reference, err := name.ParseReference(scanEvent.Image)
	if err != nil {
		impl.Logger.Errorw("error in parsing reference of image", "err", err, "image", scanEvent.Image)
		return nil, err
	}
	descriptor, err := remote.Get(reference, remote.WithTransport(roundTripper))
	if err != nil {
		impl.Logger.Errorw("error in getting image descriptor for given reference", "err", err, "reference", reference)
		return nil, err
	}
	image, err := descriptor.Image()
	if err != nil {
		impl.Logger.Errorw("error in getting image by descriptor", "err", err, "descriptor", descriptor)
		return nil, err
	}
	manifest, err := impl.GenerateClairManifestFromImage(image, reference, roundTripper)
	if err != nil {
		impl.Logger.Errorw("error in generating clair manifest from image", "err", err, "image", image)
		return nil, err
	}
	return manifest, nil
}

func (impl *ClairServiceImpl) GenerateClairManifestFromImage(image v1.Image, reference name.Reference, roundTripper http.RoundTripper) (*claircore.Manifest, error) {
	imageDigest, err := image.Digest()
	if err != nil {
		impl.Logger.Errorw("error in getting imageDigest by image", "err", err, "image", image)
		return nil, err
	}
	parsedImageDigest, err := claircore.ParseDigest(imageDigest.String())
	if err != nil {
		impl.Logger.Errorw("error in getting parsing imageDigest", "err", err, "imageDigest", imageDigest)
		return nil, err
	}
	impl.Logger.Debugw("got hash for clair manifest", "hash", parsedImageDigest)
	manifest := &claircore.Manifest{
		Hash: parsedImageDigest,
	}

	layers, err := image.Layers()
	if err != nil {
		impl.Logger.Errorw("error in getting layers from image", "err", err, "image", image)
		return nil, err
	}
	impl.Logger.Debugw("got image layers", "layers", layers, "image", image)

	//getting repository from reference
	repository := reference.Context()
	repositoryURL := url.URL{
		Scheme: repository.Scheme(),
		Host:   repository.RegistryStr(),
	}
	httpClient := http.Client{
		Transport: roundTripper,
	}
	for _, layer := range layers {
		layerDigest, err := layer.Digest()
		if err != nil {
			impl.Logger.Errorw("error in getting image digest", "err", err, "image", image)
			return nil, err
		}
		parsedLayerDigest, err := claircore.ParseDigest(layerDigest.String())
		if err != nil {
			impl.Logger.Errorw("error in parsing layerDigest", "err", err, "layerDigest", layerDigest)
			return nil, err
		}
		parsedRepositoryUrl, err := repositoryURL.Parse(path.Join("/", "v2", strings.TrimPrefix(repository.RepositoryStr(), repository.RegistryStr()), "blobs", layerDigest.String()))
		if err != nil {
			impl.Logger.Errorw("error in parsing repositoryUrl", "err", err, "repositoryUrl", repositoryURL)
			return nil, err
		}
		httpRequest, err := http.NewRequest(http.MethodGet, parsedRepositoryUrl.String(), nil)
		if err != nil {
			impl.Logger.Errorw("error in creating new http request", "err", err, "method", http.MethodGet, "url", parsedRepositoryUrl.String())
			return nil, err
		}
		httpRequest.Header.Add("Range", "bytes=0-0")
		httpResponse, err := httpClient.Do(httpRequest)
		if err != nil {
			impl.Logger.Errorw("error in sending http request", "err", err, "httpRequest", httpRequest)
			return nil, err
		}
		err = httpResponse.Body.Close()
		if err != nil {
			impl.Logger.Errorw("error in closing http request", "err", err)
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
	impl.Logger.Debugw("new request, check if index report exists for manifest hash", "manifestHash", manifestHash)

	//url - base url + "/indexer/api/v1/index_report/{manifest_hash}"
	checkIndexReportUrl, err := url.Parse(impl.ClairConfig.ClairAddress)
	if err != nil {
		impl.Logger.Errorw("error in parsing clair address url", "err", err, "clairAddress", impl.ClairConfig.ClairAddress)
		return false, err
	}
	checkIndexReportUrl.Path = path.Join(checkIndexReportUrl.Path, CLAIR_INDEX_REPORT_URL, manifestHash.String())
	request, err := http.NewRequest(http.MethodGet, checkIndexReportUrl.String(), nil)
	if err != nil {
		impl.Logger.Errorw("error in creating new http request", "err", err, "requestUrl", checkIndexReportUrl)
		return false, err
	}
	response, err := impl.HttpClient.Do(request)
	if err != nil {
		impl.Logger.Errorw("error in http request - CheckIfIndexReportExistsForManifestHash", "err", err, "manifestHash", manifestHash)
		return false, err
	}
	status := response.StatusCode
	if !(status >= 200 && status <= 299) {
		impl.Logger.Infow("index report does not exists for given manifest hash", "responseStatusCode", response.StatusCode, "manifestHash", manifestHash)
		return false, nil
	}
	impl.Logger.Debugw("received response - index report exists for given manifest hash", "manifestHash", manifestHash)
	return true, nil
}

func (impl *ClairServiceImpl) CreateIndexReportFromManifest(manifest *claircore.Manifest) error {
	impl.Logger.Debugw("new request, create index report from manifest", "manifest", manifest)
	requestBody, err := json.Marshal(manifest)
	if err != nil {
		impl.Logger.Errorw("error while marshaling request manifest", "err", err)
		return err
	}
	getIndexReportUrl, err := url.Parse(impl.ClairConfig.ClairAddress)
	if err != nil {
		impl.Logger.Errorw("error in parsing clair address url", "err", err, "clairAddress", impl.ClairConfig.ClairAddress)
		return err
	}
	getIndexReportUrl.Path = path.Join(getIndexReportUrl.Path, CLAIR_INDEX_REPORT_URL)
	request, err := http.NewRequest(http.MethodPost, getIndexReportUrl.String(), bytes.NewBuffer(requestBody))
	if err != nil {
		impl.Logger.Errorw("error in creating new http request", "err", err, "requestUrl", getIndexReportUrl, "requestBody", requestBody)
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	indexReport, err := impl.HttpClient.Do(request)
	if err != nil {
		impl.Logger.Errorw("error in http request - CreateIndexReportFromManifest", "err", err, "manifest", manifest)
		return err
	}
	impl.Logger.Debugw("created new index report from manifest", "indexReport", indexReport)
	return nil
}

func (impl *ClairServiceImpl) GetVulnerabilityReportFromManifestHash(manifestHash claircore.Digest) (*claircore.VulnerabilityReport, error) {
	impl.Logger.Debugw("new request, get vulnerability report from manifest hash", "manifestHash", manifestHash)

	//url - base url + "/matcher/api/v1/vulnerability_report/{manifest_hash}"
	getVulnerabilityReportUrl, err := url.Parse(impl.ClairConfig.ClairAddress)
	if err != nil {
		impl.Logger.Errorw("error in parsing clair address url", "err", err, "clairAddress", impl.ClairConfig.ClairAddress)
		return nil, err
	}
	getVulnerabilityReportUrl.Path = path.Join(getVulnerabilityReportUrl.Path, CLAIR_VULNERABILITY_REPORT_URL, manifestHash.String())
	request, err := http.NewRequest(http.MethodGet, getVulnerabilityReportUrl.String(), nil)
	if err != nil {
		impl.Logger.Errorw("error in creating new http request", "err", err, "requestUrl", getVulnerabilityReportUrl)
		return nil, err
	}
	response, err := impl.HttpClient.Do(request)
	if err != nil {
		impl.Logger.Errorw("error in http request - GetVulnerabilityReportFromManifestHash", "err", err, "manifestHash", manifestHash)
		return nil, err
	}

	status := response.StatusCode
	vulnerabilityReport := &claircore.VulnerabilityReport{}
	if status >= 200 && status <= 299 {
		responseBody, err := ioutil.ReadAll(response.Body)
		if err != nil {
			impl.Logger.Errorw("error in reading http response body - GetVulnerabilityReportFromManifestHash", "err", err)
			return nil, err
		}
		err = json.Unmarshal(responseBody, vulnerabilityReport)
		if err != nil {
			impl.Logger.Errorw("error in un-marshaling vulnerability report", "err", err, "responseBody", responseBody)
			return nil, err
		}
	} else {
		impl.Logger.Errorw("http request did not succeed", "response", response)
		return nil, fmt.Errorf("http request did not succeed, code: %d", status)
	}

	impl.Logger.Debugw("got vulnerability report from manifest hash", "vulnerabilityReport", vulnerabilityReport)
	return vulnerabilityReport, nil
}

func (impl *ClairServiceImpl) DeleteIndexReportFromManifestHash(manifestHash claircore.Digest) error {
	impl.Logger.Debugw("new request, delete index report from manifest hash", "manifestHash", manifestHash)

	//url - base url + "/indexer/api/v1/index_report/{manifest_hash}"
	deleteIndexReportUrl, err := url.Parse(impl.ClairConfig.ClairAddress)
	if err != nil {
		impl.Logger.Errorw("error in parsing clair address url", "err", err, "clairAddress", impl.ClairConfig.ClairAddress)
		return err
	}
	deleteIndexReportUrl.Path = path.Join(deleteIndexReportUrl.Path, CLAIR_INDEX_REPORT_URL, manifestHash.String())
	request, err := http.NewRequest(http.MethodDelete, deleteIndexReportUrl.String(), nil)
	if err != nil {
		impl.Logger.Errorw("error in creating new http request", "err", err, "requestUrl", deleteIndexReportUrl)
		return err
	}
	_, err = impl.HttpClient.Do(request)
	if err != nil {
		impl.Logger.Errorw("error in http request - DeleteIndexReportFromManifestHash", "err", err, "manifestHash", manifestHash)
		return err
	}
	impl.Logger.Debugw("deleted index report from manifest hash", "manifestHash", manifestHash)
	return nil
}
