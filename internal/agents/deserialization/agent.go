// Package deserialization implements the Deserialization Testing specialist agent.
//
// Sends Java serialized objects, PHP serialization payloads, and Python pickle
// markers to detect insecure deserialization via error messages or RCE evidence.
package deserialization

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// Agent implements the Specialist interface for Deserialization detection.
type Agent struct {
	systemPrompt string
}

// New creates a new Deserialization specialist agent.
func New() *Agent {
	return &Agent{systemPrompt: defaultSystemPrompt}
}

func (a *Agent) Name() string         { return "Deserialization Agent" }
func (a *Agent) ID() string           { return "deserialization" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// deserProbe defines one deserialization test case.
type deserProbe struct {
	label       string
	contentType string
	body        []byte
	method      string
}

// javaSerializedMagic is the Java serialization stream magic bytes (0xACED 0x0005).
var javaSerializedMagic = []byte{0xAC, 0xED, 0x00, 0x05, 0x73, 0x72} // magic + tc_object

// phpSerialPayloads are minimal PHP serialization strings that trigger common
// magic method chains when unsafely deserialized.
var phpSerialPayloads = []string{
	// Simple object that calls __wakeup
	`O:8:"stdClass":1:{s:4:"test";s:4:"data";}`,
	// Large integer string that may trigger a buffer issue in old libraries
	`a:1:{i:0;O:1:"A":1:{s:1:"a";O:1:"B":1:{s:1:"b";O:1:"C":1:{s:1:"c";s:3:"pwn";}}}}`,
}

// pythonPicklePayload is a safe pickle that simply evaluates to the string "test"
// (does NOT execute arbitrary code, but triggers pickle parsing error signatures).
var pythonPicklePayload = []byte{
	0x80, 0x04, 0x95, 0x0e, 0x00, 0x00, 0x00, 0x00, // PROTO 4 + FRAME
	0x00, 0x00, 0x00, 0x8c, 0x04, 't', 'e', 's', 't', // SHORT_BINUNICODE "test"
	0x94, 0x2e, // MEMOIZE + STOP
}

// errorSignatures are strings commonly present in deserialization error responses.
var errorSignatures = []string{
	// Java
	"java.io.StreamCorruptedException",
	"java.io.InvalidClassException",
	"ClassNotFoundException",
	"ObjectInputStream",
	"Deserialization",
	"serialVersionUID",
	// PHP
	"unserialize(): Error",
	"unserialize() expects",
	"__PHP_Incomplete_Class",
	// Python
	"_pickle.UnpicklingError",
	"pickle.UnpicklingError",
	"cannot unpickle",
}

// rceSignatures are strong indicators of successful command execution.
var rceSignatures = []string{
	"uid=", "root:", "/bin/sh", "/bin/bash",
	"Linux ", "Windows", "COMPUTERNAME=",
}

// ProcessItem sends deserialization probes to the target.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	client := newHTTPClient()
	var probes []deserProbe

	// Java serialized object probe
	probes = append(probes, deserProbe{
		label:       "java_serialized",
		contentType: "application/x-java-serialized-object",
		body:        javaSerializedMagic,
		method:      http.MethodPost,
	})

	// PHP serialization probes
	for i, pl := range phpSerialPayloads {
		probes = append(probes, deserProbe{
			label:       fmt.Sprintf("php_serial_%d", i+1),
			contentType: "application/x-www-form-urlencoded",
			body:        []byte("data=" + pl),
			method:      http.MethodPost,
		})
	}

	// Python pickle probe
	probes = append(probes, deserProbe{
		label:       "python_pickle",
		contentType: "application/octet-stream",
		body:        pythonPicklePayload,
		method:      http.MethodPost,
	})

	var findings []*base.Finding

	for _, probe := range probes {
		result := sendDeserProbe(ctx, client, targetURL, probe)
		if result.err != nil {
			continue
		}

		conf := 0.0
		evidence := map[string]interface{}{
			"label":        probe.label,
			"content_type": probe.contentType,
			"status_code":  result.statusCode,
		}

		// Check for RCE evidence first
		for _, sig := range rceSignatures {
			if strings.Contains(result.body, sig) {
				conf = 0.9
				evidence["rce_signature"] = sig
				break
			}
		}

		// Fall back to error-signature detection
		if conf == 0 {
			for _, sig := range errorSignatures {
				if strings.Contains(result.body, sig) {
					conf = 0.7
					evidence["error_signature"] = sig
					break
				}
			}
		}

		if conf == 0 {
			continue
		}

		severity := "high"
		if conf >= 0.9 {
			severity = "critical"
		}

		findings = append(findings, &base.Finding{
			Type:       "Insecure Deserialization",
			URL:        targetURL,
			Parameter:  "request_body",
			Payload:    probe.label,
			Severity:   severity,
			Confidence: conf,
			Evidence:   evidence,
			Method:     probe.method,
		})
	}

	return findings, nil
}

type deserResult struct {
	statusCode int
	body       string
	err        error
}

func sendDeserProbe(ctx context.Context, client *http.Client, targetURL string, probe deserProbe) deserResult {
	req, err := http.NewRequestWithContext(ctx, probe.method, targetURL, bytes.NewReader(probe.body))
	if err != nil {
		return deserResult{err: err}
	}
	req.Header.Set("Content-Type", probe.contentType)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return deserResult{err: err}
	}
	defer resp.Body.Close()

	lr := io.LimitReader(resp.Body, 512*1024)
	b, _ := io.ReadAll(lr)

	return deserResult{
		statusCode: resp.StatusCode,
		body:       string(b),
	}
}

func newHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: transport}
}

const defaultSystemPrompt = `You are an Insecure Deserialization specialist. You detect applications that
deserialize untrusted data, enabling remote code execution.

Probes:
- Java: send 0xACED magic bytes with Content-Type: application/x-java-serialized-object
- PHP: send O: serialized object strings via POST
- Python: send pickle PROTO 4 frames to detect parsing errors

Detection:
- 0.7 confidence on deserialization error messages in response
- 0.9 confidence on RCE evidence (uid=, /bin/bash, etc.)

Severity: CRITICAL on RCE, HIGH on error signature.`
