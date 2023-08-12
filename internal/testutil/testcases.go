package testutil

import (
	_ "embed"
	"encoding/json"
)

//go:embed testcases.json
var testCasesJSON []byte

// TestCases contains all the loaded test cases.
var TestCases = LoadTestCases()

// LoadTestCases loads the test cases from the testcases.json file.
func LoadTestCases() []TestCase {
	var testCases []TestCase
	if err := json.Unmarshal(testCasesJSON, &testCases); err != nil {
		panic(err)
	}
	return testCases
}
