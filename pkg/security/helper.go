package security

import (
	"github.com/devtron-labs/image-scanner/pkg/sql/bean"
	"github.com/devtron-labs/image-scanner/pkg/sql/repository"
)

func createCveStoreObject(name, version, fixedInVersion, severity string, userId int32) *repository.CveStore {
	cveStore := &repository.CveStore{
		Name:         name,
		Version:      version,
		FixedVersion: fixedInVersion,
	}
	lowerCaseSeverity := bean.ConvertToLowerCase(severity)
	cveStore.Severity = bean.SeverityStringToEnum(lowerCaseSeverity)
	cveStore.StandardSeverity = bean.StandardSeverityStringToEnum(lowerCaseSeverity)
	cveStore.CreateAuditLog(userId)
	return cveStore
}

func createImageScanExecutionResultObject(executionHistoryId int, vulName, packageName string, toolId int) *repository.ImageScanExecutionResult {
	return &repository.ImageScanExecutionResult{
		ImageScanExecutionHistoryId: executionHistoryId,
		CveStoreName:                vulName,
		Package:                     packageName,
		ScanToolId:                  toolId,
	}
}
