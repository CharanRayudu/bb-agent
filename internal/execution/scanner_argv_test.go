package execution

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bb-agent/mirage/internal/policy"
)

func TestDigestIsSHA256(t *testing.T) {
	got := Digest("payload")
	if len(got) != 64 || strings.Trim(got, "0123456789abcdef") != "" {
		t.Fatalf("digest=%s", got)
	}
	if Digest("payload") == Digest("payload-2") {
		t.Fatal("different payloads shared a fingerprint")
	}
}

func TestScannerPortsFilesAndOutputNames(t *testing.T) {
	httpsGW, _ := newGW(t, testAuth(policy.AutonomyL3, "https://example.com"), "93.184.216.34")
	run := func(context.Context) (string, error) { return "ran", nil }

	out, err := httpsGW.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", []byte(`{"tool":"nmap","args":["-p","443","-oN","scan.txt","example.com"]}`), run)
	if err != nil || out != "ran" {
		t.Fatalf("nmap -p 443 should match the https authorization, out=%q err=%v", out, err)
	}
	action := ToolAction("flow-1", "run_security_tool", "orchestrator", []byte(`{"tool":"nmap","args":["-p","443","-oN","scan.txt","example.com"]}`))
	if action.Host != "example.com" || action.Port != 443 || action.Scheme != "tcp" {
		t.Fatalf("endpoint=%s %s %d", action.Scheme, action.Host, action.Port)
	}
	for _, endpoint := range action.Endpoints {
		if strings.Contains(endpoint.Host, "scan") {
			t.Fatalf("output file became a destination: %+v", action.Endpoints)
		}
	}

	calls := 0
	_, err = httpsGW.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", []byte(`{"tool":"nmap","args":["-p","80","example.com"]}`), func(context.Context) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("nmap -p 80 matched an https:443 authorization, calls=%d err=%v", calls, err)
	}

	_, err = httpsGW.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", []byte(`{"tool":"nmap","args":["-p","80,443","example.com"]}`), func(context.Context) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("extra port was authorized, calls=%d err=%v", calls, err)
	}

	_, err = httpsGW.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", []byte(`{"tool":"nmap","args":["example.com"]}`), func(context.Context) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("nmap without -p ran, calls=%d err=%v", calls, err)
	}

	httpGW, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	payloads := []string{
		`{"tool":"nuclei","args":["-u","http://example.com","-o","scan.txt"]}`,
		`{"tool":"ffuf","args":["-u","http://example.com/FUZZ","-w","/usr/share/dirb/wordlists/common.txt","-o","scan.txt"]}`,
		`{"tool":"sqlmap","args":["-u","http://example.com/item?id=1","--batch","--output-dir","/tmp/scan.txt"]}`,
		`{"tool":"curl","args":["-k","-o","scan.txt","-H","Authorization: Bearer scoped","http://example.com/api"]}`,
	}
	for _, payload := range payloads {
		got, err := httpGW.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", []byte(payload), run)
		if err != nil || got != "ran" {
			t.Fatalf("%s out=%q err=%v", payload, got, err)
		}
	}
}

func TestUDPRequiresAnExplicitProtocolGrant(t *testing.T) {
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	calls := 0
	_, err := gw.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", []byte(`{"tool":"nmap","args":["-sU","-p","80","example.com"]}`), func(context.Context) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("udp scan ran without a udp grant, calls=%d err=%v", calls, err)
	}
	auth := testAuth(policy.AutonomyL3, "http://example.com")
	auth.AllowedProtocols = []string{"http", "udp"}
	udpGW, _ := newGW(t, auth, "93.184.216.34")
	out, err := udpGW.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", []byte(`{"tool":"nmap","args":["-sU","-p","80","example.com"]}`), func(context.Context) (string, error) {
		return "ran", nil
	})
	if err != nil || out != "ran" {
		t.Fatalf("granted udp scan did not run, out=%q err=%v", out, err)
	}
	_, err = gw.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", []byte(`{"tool":"sqlmap","args":["-u","http://example.com","--os-shell"]}`), func(context.Context) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("sqlmap os-shell ran, calls=%d err=%v", calls, err)
	}
}

func TestTargetListIsAuthorizedAndMissingFileIsDenied(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(list, []byte("example.com\n# comment\nevil.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	calls := 0
	_, err := gw.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", []byte(`{"tool":"nuclei","args":["-l","`+escapeJSON(list)+`"]}`), func(context.Context) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("target list containing evil.example ran, calls=%d err=%v", calls, err)
	}
	_, err = gw.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", []byte(`{"tool":"nuclei","args":["-l","`+escapeJSON(filepath.Join(dir, "missing.txt"))+`"]}`), func(context.Context) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("missing target list ran, calls=%d err=%v", calls, err)
	}
}

func TestRelativeTargetListInTheFlowWorkspaceIsAuthorized(t *testing.T) {
	root := t.TempDir()
	t.Setenv("MIRAGE_WORKSPACE_ROOT", root)
	dir, err := EnsureWorkspace("flow-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts.txt"), []byte("example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	out, err := gw.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", []byte(`{"tool":"nuclei","args":["-l","hosts.txt"]}`), func(context.Context) (string, error) {
		return "ran", nil
	})
	if err != nil || out != "ran" {
		t.Fatalf("workspace target list out=%q err=%v", out, err)
	}
}

func TestRawRequestFileSuppliesTheHost(t *testing.T) {
	dir := t.TempDir()
	req := filepath.Join(dir, "request.req")
	body := "GET /api/v1/user HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if err := os.WriteFile(req, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	gw, _ := newGW(t, testAuth(policy.AutonomyL3, "http://example.com"), "93.184.216.34")
	out, err := gw.ExecuteTool(context.Background(), "flow-1", "run_security_tool", "orchestrator", []byte(`{"tool":"sqlmap","args":["-r","`+escapeJSON(req)+`","--batch"]}`), func(context.Context) (string, error) {
		return "ran", nil
	})
	if err != nil || out != "ran" {
		t.Fatalf("sqlmap request file out=%q err=%v", out, err)
	}
}

func escapeJSON(path string) string {
	return strings.ReplaceAll(path, `\`, `\\`)
}
