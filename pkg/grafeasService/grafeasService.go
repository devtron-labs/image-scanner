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

package grafeasService

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/grafeas"
	"github.com/optiopay/klar/clair"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
)

type GrafeasConfig struct {
	ProjectId string `env:"PROJECT_ID" envDefault:"projects/devtron-project-id"`
}

func GetGrafeasClient() *grafeas.APIClient {
	client := grafeas.NewAPIClient(&grafeas.Configuration{
		BasePath:      "http://localhost:8082",
		DefaultHeader: make(map[string]string),
	})
	return client
}

type GrafeasService interface {
	GetNotesById(noteID string) (*grafeas.V1beta1Note, error)
	GetAllNotes() ([]*grafeas.V1beta1Note, error)
	CreateNote(vs []*clair.Vulnerability, event *common.ImageScanEvent) (bool, error)
	CreateOccurrence(v *clair.Vulnerability, noteName string, event *common.ImageScanEvent) (bool, error)
	GetOccurrenceById(noteID string) (*grafeas.V1beta1Occurrence, error)
	GetAllOccurrence() ([]*grafeas.V1beta1Occurrence, error)
}

type GrafeasServiceImpl struct {
	logger     *zap.SugaredLogger
	client     *grafeas.APIClient
	httpClient *http.Client
}

func NewKlarServiceImpl(logger *zap.SugaredLogger, client *grafeas.APIClient, httpClient *http.Client) *GrafeasServiceImpl {
	return &GrafeasServiceImpl{
		logger:     logger,
		client:     client,
		httpClient: httpClient,
	}
}

const basePath string = "http://localhost:8081/v1beta1"
const projectID string = "projects/devtron_test_project"

func (impl *GrafeasServiceImpl) GetNotesById(noteID string) (*grafeas.V1beta1Note, error) {
	noteID = "devtron-note-id"
	/*
		note := fmt.Sprintf("%s/notes/%s", projectID, noteID)
		ctx := context.Background()
		client := grafeas.NewAPIClient(&grafeas.Configuration{BasePath: "http://localhost:8081", DefaultHeader: make(map[string]string)})
		resp, httpResponse, err := impl.client.GrafeasV1Beta1Api.GetNote(ctx, note)
		if err != nil {
			impl.logger.Errorw("Failed to data from grafeas", "err", err)
			return err
		}
		fmt.Println(resp)
		fmt.Println(httpResponse)
	*/
	url := fmt.Sprintf("%s/%s/notes/%s", basePath, projectID, noteID)
	httpResponse, err := impl.httpGet(url)
	if err != nil {
		impl.logger.Errorw("Failed to get from grafeas", "err", err)
		return nil, err
	}

	defer httpResponse.Body.Close()
	var noteResponse grafeas.V1beta1Note
	resBody, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		impl.logger.Errorw("error in parsing response ", "err", err)
		return nil, err
	}
	if httpResponse.StatusCode >= 200 && httpResponse.StatusCode <= 300 {
		err = json.Unmarshal(resBody, &noteResponse)
		if err != nil {
			impl.logger.Errorw("error in resp Unmarshal ", "err", err)
			return nil, err
		}
	}
	impl.logger.Errorw("api response", "status code", httpResponse.StatusCode)
	impl.logger.Info(noteResponse)
	return &noteResponse, nil
}

func (impl *GrafeasServiceImpl) GetAllNotes() ([]*grafeas.V1beta1Note, error) {

	/*
		ctx := context.Background()
		client := grafeas.NewAPIClient(&grafeas.Configuration{BasePath: "http://localhost:8081"})
		resp, httpResponse, err := impl.client.GrafeasV1Beta1Api.ListNotes(ctx, projectID, nil)
		if err != nil {
			impl.logger.Errorw("Failed to get from grafeas", "err", err)
			return err
		}
		fmt.Println(resp)
		fmt.Println(httpResponse)
	*/
	url := fmt.Sprintf("%s/%s/notes", basePath, projectID)
	httpResponse, err := impl.httpGet(url)
	if err != nil {
		impl.logger.Errorw("Failed to get from grafeas", "err", err)
		return nil, err
	}
	defer httpResponse.Body.Close()
	var noteResponse []*grafeas.V1beta1Note
	resBody, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		impl.logger.Errorw("error in parsing response ", "err", err)
		return nil, err
	}
	if httpResponse.StatusCode >= 200 && httpResponse.StatusCode <= 300 {
		err = json.Unmarshal(resBody, &noteResponse)
		if err != nil {
			impl.logger.Errorw("error in resp Unmarshal ", "err", err)
			return nil, err
		}
	}
	impl.logger.Errorw("api response", "status code", httpResponse.StatusCode)
	impl.logger.Info(noteResponse)
	return noteResponse, nil
}

func (impl *GrafeasServiceImpl) CreateNote(vs []*clair.Vulnerability, event *common.ImageScanEvent) (bool, error) {
	for _, item := range vs {
		var vulnerabilityDetails []grafeas.VulnerabilityDetail
		vulnerabilityDetails = append(vulnerabilityDetails, grafeas.VulnerabilityDetail{
			CpeUri:   item.NamespaceName,
			Package_: item.FeatureName,
		})
		//vulnerability name here consider as noteID
		noteID := item.Name
		kind := grafeas.VULNERABILITY_V1beta1NoteKind
		vulnerabilityVulnerability := grafeas.VulnerabilityVulnerability{}
		vulnerabilityVulnerability.Details = vulnerabilityDetails
		req := grafeas.V1beta1Note{
			Name:             fmt.Sprintf("%s/notes/%s", projectID, noteID),
			ShortDescription: "A short description of the note",
			Kind:             &kind,
			Vulnerability:    &vulnerabilityVulnerability,
		}

		/*
			ctx := context.Background()
			client := grafeas.NewAPIClient(&grafeas.Configuration{BasePath: "http://localhost:8081"})
			resp, httpResponse, err := impl.client.GrafeasV1Beta1Api.CreateNote(ctx, projectID, req)
			if err != nil {
				impl.logger.Errorw("Failed to post to grafeas", "err", err)
				return err
			}
		*/

		url := fmt.Sprintf("%s/%s/notes?note_id=%s", basePath, projectID, noteID)
		b, err := json.Marshal(&req)
		if err != nil {
			b = []byte("OK")
		}
		reqBody := []byte(b)
		httpResponse, err := impl.httpPost(reqBody, url)
		if err != nil {
			impl.logger.Errorw("Failed to post to grafeas", "err", err)
			return false, err
		}
		impl.logger.Error(httpResponse)

		_, err = impl.CreateOccurrence(item, req.Name, event)
		if err != nil {
			impl.logger.Errorw("Failed to post to grafeas", "err", err)
			return false, err
		}
	}
	return true, nil
}

func (impl *GrafeasServiceImpl) CreateOccurrence(v *clair.Vulnerability, noteName string, event *common.ImageScanEvent) (bool, error) {
	kind := grafeas.VULNERABILITY_V1beta1NoteKind
	versionKind := grafeas.NORMAL_VersionVersionKind
	vulnerabilityVulnerability := grafeas.V1beta1vulnerabilityDetails{}
	var packageIssues []grafeas.VulnerabilityPackageIssue
	packageIssue := grafeas.VulnerabilityPackageIssue{
		AffectedLocation: &grafeas.VulnerabilityVulnerabilityLocation{CpeUri: "devtron package storage", Package_: "devtron package", Version: &grafeas.PackageVersion{Name: "devtron package", Kind: &versionKind}},
		FixedLocation:    &grafeas.VulnerabilityVulnerabilityLocation{CpeUri: "devtron package storage", Package_: "devtron package", Version: &grafeas.PackageVersion{Name: "devtron package", Kind: &versionKind}},
	}
	packageIssues = append(packageIssues, packageIssue)
	vulnerabilityVulnerability.PackageIssue = packageIssues
	occurrence := grafeas.V1beta1Occurrence{
		Kind: &kind,
		Resource: &grafeas.V1beta1Resource{
			Uri: event.Image,
		},
		NoteName:      noteName,
		Vulnerability: &vulnerabilityVulnerability,
	}
	/*
		ctx := context.Background()
		resp, httpResponse, err := impl.client.GrafeasV1Beta1Api.CreateOccurrence(ctx, projectID, occurrence)
		if err != nil {
			impl.logger.Errorw("Failed to post to grafeas", "err", err)
			return err
		}
		fmt.Print(resp)
		fmt.Print(httpResponse)
	*/

	url := fmt.Sprintf("%s/%s/occurrences", basePath, projectID)
	b, err := json.Marshal(&occurrence)
	if err != nil {
		b = []byte("OK")
	}
	reqBody := []byte(b)
	httpResponse, err := impl.httpPost(reqBody, url)
	if err != nil {
		impl.logger.Errorw("Failed to post to grafeas", "err", err)
		return false, err
	}
	impl.logger.Error(httpResponse)
	return true, nil
}

func (impl *GrafeasServiceImpl) GetOccurrenceById(occurrenceID string) (*grafeas.V1beta1Occurrence, error) {
	occurrenceID = "e187df4c-0f42-4951-a919-6ef5b7874176"
	url := fmt.Sprintf("%s/%s/occurrences/%s", basePath, projectID, occurrenceID)
	httpResponse, err := impl.httpGet(url)
	if err != nil {
		impl.logger.Errorw("Failed to get from grafeas", "err", err)
		return nil, err
	}

	defer httpResponse.Body.Close()
	var occurrenceResponse grafeas.V1beta1Occurrence
	resBody, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		impl.logger.Errorw("error in parsing response ", "err", err)
		return nil, err
	}
	if httpResponse.StatusCode >= 200 && httpResponse.StatusCode <= 300 {
		err = json.Unmarshal(resBody, &occurrenceResponse)
		if err != nil {
			impl.logger.Errorw("error in resp Unmarshal ", "err", err)
			return nil, err
		}
	}
	impl.logger.Errorw("api response", "status code", httpResponse.StatusCode)
	impl.logger.Info(occurrenceResponse)
	return &occurrenceResponse, nil
}

func (impl *GrafeasServiceImpl) GetAllOccurrence() ([]*grafeas.V1beta1Occurrence, error) {
	url := fmt.Sprintf("%s/%s/notes", basePath, projectID)
	httpResponse, err := impl.httpGet(url)
	if err != nil {
		impl.logger.Errorw("Failed to get from grafeas", "err", err)
		return nil, err
	}
	defer httpResponse.Body.Close()
	var occurrenceResponse []*grafeas.V1beta1Occurrence
	resBody, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		impl.logger.Errorw("error in parsing response ", "err", err)
		return nil, err
	}
	if httpResponse.StatusCode >= 200 && httpResponse.StatusCode <= 300 {
		err = json.Unmarshal(resBody, &occurrenceResponse)
		if err != nil {
			impl.logger.Errorw("error in resp Unmarshal ", "err", err)
			return nil, err
		}
	}
	impl.logger.Errorw("api response", "status code", httpResponse.StatusCode)
	impl.logger.Info(occurrenceResponse)
	return occurrenceResponse, nil
}

func (impl *GrafeasServiceImpl) httpPost(reqBody []byte, url string) (*http.Response, error) {
	impl.logger.Debugw("request", "body", string(reqBody))
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		impl.logger.Errorw("error while creating post request", "err", err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := impl.httpClient.Do(req)
	if err != nil {
		impl.logger.Errorw("error while http Do request ", "err", err)
		return nil, err
	}
	impl.logger.Infow("response from http Do request", "status code", resp.StatusCode)
	return resp, err
}

func (impl *GrafeasServiceImpl) httpGet(url string) (*http.Response, error) {
	impl.logger.Debugw("request", "url", url)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		impl.logger.Errorw("error while creating get request", "err", err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := impl.httpClient.Do(req)
	if err != nil {
		impl.logger.Errorw("error while http Do request ", "err", err)
		return nil, err
	}
	impl.logger.Infow("response from http Do request", "status code", resp.StatusCode)
	return resp, err
}
