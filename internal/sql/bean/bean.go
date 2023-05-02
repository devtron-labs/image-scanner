package bean

import (
	"fmt"
	"strconv"
)

const (
	ScanOutputDirectory      = "/devtronimagescan"
	NullProcessIndex         = -1
	JsonOutputFileNameSuffix = "_out.json"
	ClairTool                = "clair"
	Version4                 = "v4"
	Version2                 = "v2"
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
	Name           string `json:"name"`
	Package        string `json:"package"`
	PackageVersion string `json:"packageVersion"`
	FixedInVersion string `json:"fixedInVersion"`
	Severity       string `json:"severity"`
}

type Severity int

const (
	Low Severity = iota
	Medium
	High
	Critical
)

func (sev Severity) String() string {
	return [...]string{"Low", "Medium", "High", "Critical"}[sev]
}

var ConvertToSeverity = map[string]Severity{
	"Low":      Low,
	"Medium":   Medium,
	"High":     High,
	"Critical": Critical,
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
