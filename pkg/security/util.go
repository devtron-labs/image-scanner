package security

import (
	"fmt"
	"github.com/devtron-labs/image-scanner/pkg/sql/bean"
	"os"
	"path"
	"strconv"
)

func WriteToFile(filePath string, data []byte) error {

	// Write chart data to file
	err := os.WriteFile(filePath, data, 0644)
	if err != nil {
		return fmt.Errorf("error writing chart data:%w", err)
	}
	return nil
}

func CreateFolderForOutputData(executionHistoryModelId int) string {
	executionHistoryModelIdStr := strconv.Itoa(executionHistoryModelId)
	executionHistoryDirPath := path.Join(bean.ScanOutputDirectory, executionHistoryModelIdStr)
	return executionHistoryDirPath
}
