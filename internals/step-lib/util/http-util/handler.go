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

package http_util

import (
	"context"
	"fmt"
	common_util "github.com/devtron-labs/image-scanner/internals/step-lib/util/common-util"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const (
	HttpMethodTypeGet    = "GET"
	HttpMethodTypePost   = "POST"
	HttpMethodTypePut    = "PUT"
	HttpMethodTypeDelete = "DELETE"
)

func HandleHTTPRequest(requestUrl string, methodType string, headers map[string]string, queryParams url.Values, requestBody io.Reader, outputFileName string, ctx context.Context) ([]byte, error) {
	client := http.Client{}
	parsedUrl, err := url.Parse(requestUrl)
	if err != nil {
		return nil, err
	}
	if methodType == HttpMethodTypeGet {
		q := parsedUrl.Query()
		for k, v := range queryParams {
			q.Set(k, strings.Join(v, ","))
		}
		parsedUrl.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, methodType, parsedUrl.String(), requestBody)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, fmt.Errorf("error in http request - %s, received empty response", parsedUrl.String())
	}
	responseData, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error in http request - %s, resp: %s", parsedUrl, responseData)
	}
	if outputFileName != "" && responseData != nil {
		err = common_util.WriteFile(outputFileName, responseData)
		if err != nil {
			log.Println("error in writing http output to file", "err", err)
			return nil, err
		}
	}
	return responseData, nil
}
