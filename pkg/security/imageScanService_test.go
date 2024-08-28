package security

import (
	"fmt"
	"github.com/devtron-labs/image-scanner/pkg/logger"
	"github.com/tidwall/gjson"
	"os"
	"testing"
)

const jsonKeys = "[    \n      { \n        \"pathToResultArray\": \"Results\",\n        \"pathToVulnerabilitiesArray\": \"Vulnerabilities\",\n        \"vulnerabilityData\":{\n       \t\t\"name\": \"VulnerabilityID\",\n        \t\"package\": \"PkgName\", \n        \t\"packageVersion\": \"InstalledVersion\",\n        \t\"fixedInVersion\": \"FixedVersion\",\n        \t\"severity\": \"Severity\"\n        },\n        \"resultData\":{\n  \t\t\t\"target\":\"Target\",\n        \t\"class\":\"Class\",\n        \t\"type\":\"Type\"   \n       }\n      }\n]"

func TestScan(t *testing.T) {
	bytes, err := os.ReadFile("testTrivyScanResultV2.json")
	if err != nil {
		t.Fail()
	}

	logger, _ := logger.InitLogger()
	impl := ImageScanServiceImpl{Logger: logger}
	out, err := impl.getImageScanOutputObjectsV2(bytes, jsonKeys)
	fmt.Println(out, err)
	if err != nil || len(out) == 0 {
		t.Fail()
	}

	cnt, err := countVuln(bytes)
	if err != nil {
		t.Fail()
	}

	if cnt != len(out) {
		t.Fail()
	}
}

func countVuln(jsonStr []byte) (int, error) {
	result := gjson.Get(string(jsonStr), "Results")
	if !result.Exists() {
		return 0, nil
	}

	targetCountMap := make(map[string]int)

	result.ForEach(func(_, nestedValue gjson.Result) bool {
		if nestedValue.IsObject() {
			count := 0
			targetName := nestedValue.Get("Target").String()
			if nestedValue.Get("Vulnerabilities").IsArray() {
				nestedValue.Get("Vulnerabilities").ForEach(func(_, vul gjson.Result) bool {
					count++
					return true
				})
			}
			targetCountMap[targetName] += count
		}
		return true
	})

	count := 0
	for _, cnt := range targetCountMap {
		count += cnt
	}
	return count, nil
}
