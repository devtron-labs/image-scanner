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

package bean

import (
	"fmt"
	"strconv"
	"strings"
)

const UserSystemId = 1

const (
	ScanOutputDirectory      = "/security/devtronimagescan" // This is not configurable due to permissions for devtron-user
	NullProcessIndex         = -1
	JsonOutputFileNameSuffix = "_out.json"
	ScannerTypeClairV4       = "CLAIRV4"
	ScannerTypeClairV2       = "CLAIRV2"
	ScannerTypeTrivy         = "TRIVY"
	ScanToolClair            = "CLAIR"
	ScanToolVersion2         = "V2"
	ScanToolVersion4         = "V4"
	SbomOutputFileNameSuffix = "_out.json"
)

type ScanExecutionType string

const (
	ScanExecutionTypeHttp ScanExecutionType = "HTTP"
	ScanExecutionTypeCli  ScanExecutionType = "CLI"
)

type ScanExecutionProcessState int

const (
	ScanExecutionProcessStateFailed    ScanExecutionProcessState = iota - 1 //resolved value = -1
	ScanExecutionProcessStateRunning                                        //resolved value =  0
	ScanExecutionProcessStateCompleted                                      //resolved value =  1
)

type ImageScanOutputObject struct {
	TargetName     string `json:"targetName"`
	Class          string `json:"class"`
	Type           string `json:"type"`
	Name           string `json:"name"`
	Package        string `json:"package"`
	PackageVersion string `json:"packageVersion"`
	FixedInVersion string `json:"fixedInVersion"`
	Severity       string `json:"severity"`
}

// Mapping is the used to store mappings of fields in ImageScanOutputObject and the path at which they are present in stepOutput
type Mapping map[string]string

const (
	MappingKeyPathToResultDataKeys        = "resultData"
	MappingKeyPathToVulnerabilityDataKeys = "vulnerabilityData"
	MappingKeyPathToResultsArray          = "pathToResultArray"
	MappingKeyPathToVulnerabilitiesArray  = "pathToVulnerabilitiesArray"
	MappingKeyName                        = "name"
	MappingKeyPackage                     = "package"
	MappingKeyPackageVersion              = "packageVersion"
	MappingKeyFixedInVersion              = "fixedInVersion"
	MappingKeySeverity                    = "severity"
	MappingTarget                         = "target"
	MappingType                           = "type"
	MappingClass                          = "class"
)

type Severity int

const (
	HIGH     string = "high"
	CRITICAL string = "critical"
	SAFE     string = "safe"
	LOW      string = "low"
	MEDIUM   string = "medium"
	MODERATE string = "moderate"
	UNKNOWN  string = "unknown"
)

const (
	Low Severity = iota
	Medium
	Critical
	High
	Safe
	Unknown
)

func (sev Severity) String() string {
	return [...]string{LOW, MEDIUM, CRITICAL, HIGH, SAFE, UNKNOWN}[sev]
}
func ConvertToLowerCase(input string) string {
	return strings.ToLower(input)
}

func SeverityStringToEnum(severity string) Severity {
	if severity == LOW || severity == SAFE {
		return Low
	} else if severity == MEDIUM || severity == MODERATE {
		return Medium
	} else if severity == HIGH || severity == CRITICAL {
		return Critical
	} else if severity == UNKNOWN {
		return Unknown
	}
	return Low
}

func StandardSeverityStringToEnum(severity string) Severity {
	if severity == LOW {
		return Low
	} else if severity == MEDIUM || severity == MODERATE {
		return Medium
	} else if severity == HIGH {
		return High
	} else if severity == CRITICAL {
		return Critical
	} else if severity == SAFE {
		return Safe
	} else if severity == UNKNOWN {
		return Unknown
	}
	return Low
}

type VariableFormat string

const (
	VariableFormatString  VariableFormat = "STRING"
	VariableFormatBoolean VariableFormat = "BOOLEAN"
	VariableFormatNumber  VariableFormat = "NUMBER"
)

func ConvertVariableFormat(value string, varFormat VariableFormat) (interface{}, error) {
	switch varFormat {
	case VariableFormatString:
		return value, nil
	case VariableFormatNumber:
		return strconv.ParseFloat(value, 8)
	case VariableFormatBoolean:
		return strconv.ParseBool(value)
	default:
		return nil, fmt.Errorf("format not supported")
	}
}

type UserInfo struct {
	Id          int32    `json:"id" validate:"number"`
	EmailId     string   `json:"email_id" validate:"required"`
	Roles       []string `json:"roles,omitempty"`
	AccessToken string   `json:"access_token,omitempty"`
	Exist       bool     `json:"-"`
	UserId      int32    `json:"-"` // created or modified user id
	Status      string   `json:"status,omitempty"`
	Groups      []string `json:"groups"`
	SuperAdmin  bool     `json:"superAdmin,notnull"`
}
