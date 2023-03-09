package common_util

import (
	"fmt"
	"io/fs"
	"log"
	"os"
)

const (
	OutputFilePrefix                        = "tmp-output" //TODO: should this be csv?
	DefaultFileCreatePermission fs.FileMode = 0666
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
