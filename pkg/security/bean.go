package security

import (
	"github.com/devtron-labs/image-scanner/common"
	"github.com/devtron-labs/image-scanner/pkg/sql/repository"
)

type ScanCodeRequest struct {
	ScanEvent               *common.ImageScanEvent
	Tool                    *repository.ScanToolMetadata
	ExecutionHistory        *repository.ImageScanExecutionHistory
	ExecutionHistoryDirPath string
}
