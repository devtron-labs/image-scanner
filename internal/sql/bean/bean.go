package bean

const (
	ScanOutputDirectory      = "/devtronimagescan"
	NullProcessIndex         = -1
	JsonOutputFileNameSuffix = "_out.json"
)

type ScanExecutionType string

const (
	ScanExecutionTypeHttp ScanExecutionType = "HTTP"
	ScanExecutionTypeCli  ScanExecutionType = "CLI"
)

type ScanExecutionProcessState int

const (
	ScanExecutionProcessStateFailed    = iota - 1 //resolved value = -1
	ScanExecutionProcessStateRunning              //resolved value =  0
	ScanExecutionProcessStateCompleted            //resolved value =  1
)
