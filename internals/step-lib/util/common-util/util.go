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

package common_util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"os"
)

const (
	OutputFilePrefix                        = "tmp-output" //TODO: should this be csv?
	DefaultFileCreatePermission fs.FileMode = 0755
)

// CreateFile takes a unique identifier for a file and creates it in the current working directory
// it returns name of the file created along with any error if encountered
func CreateFile(fileIdentifier string) (string, error) {
	fileName := fmt.Sprintf("%s-%s", OutputFilePrefix, fileIdentifier)
	file, err := os.Create(fileName)
	if err != nil {
		log.Println("error in creating output file")
		return fileName, err
	}
	err = file.Chmod(DefaultFileCreatePermission)
	if err != nil {
		log.Println("error updating file permission", "err", err, "file", file.Name(), "desiredFilePermission", DefaultFileCreatePermission)
		return fileName, err
	}
	return fileName, nil
}

func WriteFile(fileName string, data []byte) (err error) {
	err = os.WriteFile(fileName, data, DefaultFileCreatePermission)
	if err != nil {
		log.Println("error in writing to file", "err", err, "fileName", fileName)
		return err
	}
	return nil
}

func ReadFile(fileName string) ([]byte, error) {
	op, err := os.ReadFile(fileName)
	if err != nil {
		log.Println("error in reading file", "err", err, "fileName", fileName)
		return nil, err
	}
	return op, nil
}

func ParseJsonTemplate(inputTemplate string, data []byte) (string, error) {
	tmpl := template.Must(template.New("").Funcs(template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"len": func(sliceIf interface{}) int {
			if slice, ok := sliceIf.([]any); ok {
				return len(slice)
			}
			return 0
		},
	}).Parse(inputTemplate))
	jsonMap := map[string]interface{}{}
	err := json.Unmarshal(data, &jsonMap)
	if err != nil {
		log.Println("error in unmarshalling", "err", err)
		return "", err
	}
	buf := &bytes.Buffer{}
	//this check handles the case when Results key is not found in trivy scan report
	if _, ok := jsonMap["Results"]; !ok {
		return "[]", nil
	}
	err = tmpl.Execute(buf, jsonMap)
	if err != nil {
		log.Println("error in executing template", "err", err)
		return "", err
	}
	return buf.String(), nil
}
