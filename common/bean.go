package common

import (
	"github.com/optiopay/klar/clair"
	"github.com/quay/claircore"
	"strings"
	"time"
)

const (
	AWSAccessKeyId     = "AWS_ACCESS_KEY_ID"
	AWSSecretAccessKey = "AWS_SECRET_ACCESS_KEY"
	AWSRegion          = "AWS_DEFAULT_REGION"
	Username           = "USERNAME"
	Password           = "PASSWORD"
	GCR_FILE_PATH      = "FILE_PATH"
	IMAGE_NAME         = "IMAGE_NAME"
	OUTPUT_FILE_PATH   = "OUTPUT_FILE_PATH"
)

const (
	SHELL_COMMAND = "sh"
	COMMAND_ARGS  = "-c"
)

type RegistryType string

type ImageScanRenderDto struct {
	RegistryType       RegistryType `json:"-"`
	AWSAccessKeyId     string       `json:"awsAccessKeyId,omitempty" `
	AWSSecretAccessKey string       `json:"awsSecretAccessKey,omitempty"`
	AWSRegion          string       `json:"awsRegion"`
	Username           string       `json:"username,omitempty"`
	Password           string       `json:"password,omitempty"`
	Image              string       `json:"image"`
	OutputFilePath     string       `json:"-"`
}

type ImageScanEvent struct {
	Image            string `json:"image"`
	ImageDigest      string `json:"imageDigest"`
	AppId            int    `json:"appId"`
	EnvId            int    `json:"envId"`
	PipelineId       int    `json:"pipelineId"`
	CiArtifactId     int    `json:"ciArtifactId"`
	UserId           int    `json:"userId"`
	AccessKey        string `json:"accessKey"`
	SecretKey        string `json:"secretKey"`
	Token            string `json:"token"`
	AwsRegion        string `json:"awsRegion"`
	DockerRegistryId string `json:"dockerRegistryId"`
	ScanHistoryId    int    `json:"scanHistoryId"`
}

type ScanEventResponse struct {
	RequestData         *ImageScanEvent            `json:"requestData"`
	ResponseDataClairV4 []*claircore.Vulnerability `json:"responseDataClairV4"`
	ResponseDataClairV2 []*clair.Vulnerability     `json:"ResponseDataClairV2"`
}

const (
	ScanObjectType_APP   string = "app"
	ScanObjectType_CHART string = "chart"
	ScanObjectType_POD   string = "pod"
)

type ImageScanRequest struct {
	ScanExecutionId       int    `json:"ScanExecutionId"`
	ImageScanDeployInfoId int    `json:"imageScanDeployInfo"`
	AppId                 int    `json:"appId"`
	EnvId                 int    `json:"envId"`
	ArtifactId            int    `json:"artifactId"`
	CVEName               string `json:"CveName"`
	Image                 string `json:"image"`
	ViewFor               int    `json:"viewFor"`
	Offset                int    `json:"offset"`
	Size                  int    `json:"size"`
	PipelineId            int    `json:"pipelineId"`
	PipelineType          string `json:"pipelineType"`
}

type ImageScanHistoryListingResponse struct {
	Offset                   int                         `json:"offset"`
	Size                     int                         `json:"size"`
	ImageScanHistoryResponse []*ImageScanHistoryResponse `json:"scanList"`
}

type ImageScanHistoryResponse struct {
	ImageScanDeployInfoId int            `json:"imageScanDeployInfoId"`
	AppId                 int            `json:"appId"`
	EnvId                 int            `json:"envId"`
	Name                  string         `json:"name"`
	Type                  string         `json:"type"`
	Environment           string         `json:"environment"`
	LastChecked           time.Time      `json:"lastChecked"`
	Image                 string         `json:"image,omitempty"`
	SeverityCount         *SeverityCount `json:"severityCount,omitempty"`
}

type ImageScanExecutionDetail struct {
	ImageScanDeployInfoId int                `json:"imageScanDeployInfoId"`
	AppId                 int                `json:"appId,omitempty"`
	EnvId                 int                `json:"envId,omitempty"`
	AppName               string             `json:"appName,omitempty"`
	EnvName               string             `json:"envName,omitempty"`
	ArtifactId            int                `json:"artifactId,omitempty"`
	Image                 string             `json:"image,omitempty"`
	PodName               string             `json:"podName,omitempty"`
	ReplicaSet            string             `json:"replicaSet,omitempty"`
	Vulnerabilities       []*Vulnerabilities `json:"vulnerabilities,omitempty"`
	SeverityCount         *SeverityCount     `json:"severityCount,omitempty"`
	ExecutionTime         time.Time          `json:"executionTime,omitempty"`
}

type Vulnerabilities struct {
	CVEName    string `json:"cveName"`
	Severity   string `json:"severity"`
	Package    string `json:"package"`
	CVersion   string `json:"currentVersion"`
	FVersion   string `json:"fixedVersion"`
	Permission string `json:"permission"`
}

type SeverityCount struct {
	High     int `json:"high"`
	Moderate int `json:"moderate"`
	Low      int `json:"low"`
}

func RemoveTrailingComma(jsonString string) string {
	if strings.HasSuffix(jsonString, ",]") {
		return jsonString[:len(jsonString)-2] + jsonString[len(jsonString)-1:]
	}
	return jsonString
}
