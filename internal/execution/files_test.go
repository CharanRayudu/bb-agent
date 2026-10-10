package execution

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScannerTargetListAndRawRequestFileParsing(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Target list file (-iL)
	targetListPath := filepath.Join(tmpDir, "targets.txt")
	targetListContent := "target1.example.com\n# comment\nhttp://target2.example.com:8080\n"
	if err := os.WriteFile(targetListPath, []byte(targetListContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmdIL := "nmap -iL " + targetListPath
	argvIL := splitArgs(cmdIL)
	destsIL := commandDestinations(cmdIL, argvIL)

	if len(destsIL) < 2 {
		t.Fatalf("Expected at least 2 destinations from -iL file, got %v", destsIL)
	}

	// 2. Raw HTTP request file (-r)
	reqFilePath := filepath.Join(tmpDir, "request.req")
	reqFileContent := "GET /api/v1/user HTTP/1.1\r\nHost: reqtarget.example.com\r\nUser-Agent: test\r\n\r\n"
	if err := os.WriteFile(reqFilePath, []byte(reqFileContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmdR := "sqlmap -r " + reqFilePath
	argvR := splitArgs(cmdR)
	destsR := commandDestinations(cmdR, argvR)

	foundHost := false
	for _, d := range destsR {
		if d == "reqtarget.example.com" {
			foundHost = true
			break
		}
	}
	if !foundHost {
		t.Fatalf("Expected Host header target 'reqtarget.example.com' from raw request file, got %v", destsR)
	}
}
