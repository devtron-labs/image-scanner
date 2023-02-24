package http_util

import (
	"encoding/json"
	"fmt"
	"io"
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

func HandleHTTPRequest[Any any](requestUrl string, methodType string, headers map[string]string, queryParams url.Values, requestBody io.Reader, responseType Any) (Any, error) {
	client := http.Client{}
	parsedUrl, err := url.Parse(requestUrl)
	if err != nil {
		return responseType, err
	}
	if methodType == HttpMethodTypeGet {
		q := parsedUrl.Query()
		for k, v := range queryParams {
			q.Set(k, strings.Join(v, ","))
		}
		parsedUrl.RawQuery = q.Encode()
	}
	req, err := http.NewRequest(methodType, parsedUrl.String(), requestBody)
	if err != nil {
		return responseType, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := client.Do(req)
	if err != nil {
		return responseType, err
	}
	if res == nil {
		return responseType, fmt.Errorf("error in http request - %s, received empty response", parsedUrl.String())
	}
	responseData, err := io.ReadAll(res.Body)
	if err != nil {
		return responseType, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return responseType, fmt.Errorf("error in http request - %s, resp: %s", parsedUrl, responseData)
	}
	var responseObject Any
	err = json.Unmarshal(responseData, &responseObject)
	if err != nil {
		fmt.Printf("error in unmarshaling: %v", err)
		return responseType, err
	}
	return responseObject, nil
}
