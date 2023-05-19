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
	OutputFilePrefix                          = "tmp-output" //TODO: should this be csv?
	DefaultFileCreatePermission   fs.FileMode = 0666
	DefaultFolderCreatePermission fs.FileMode = 0777
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
	}).Parse(inputTemplate))
	jsonMap := map[string]interface{}{}
	err := json.Unmarshal(data, &jsonMap)
	if err != nil {
		log.Println("error in unmarshalling", "err", err)
		return "", err
	}
	buf := &bytes.Buffer{}
	err = tmpl.Execute(buf, jsonMap)
	if err != nil {
		log.Println("error in executing template", "err", err)
		return "", err
	}
	return buf.String(), nil
}
