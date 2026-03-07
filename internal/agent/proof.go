package agent

import (
	"fmt"
	"strings"
)

type proofClass string

const (
	proofClassNone            proofClass = ""
	proofClassRequestResponse proofClass = "request_response"
	proofClassBrowser         proofClass = "browser"
	proofClassTiming          proofClass = "timing"
	proofClassOOB             proofClass = "oob"
)

func classifyFindingProof(f *Finding) (proofClass, string) {
	if f == nil {
		return proofClassNone, "finding is nil"
	}
	if len(f.Evidence) == 0 {
		return proofClassNone, "missing evidence"
	}

	ev := f.Evidence

	if hasAnyEvidenceValue(ev, "oob_type", "oob_remote", "oob_token", "callback", "oob_raw_data") {
		return proofClassOOB, "confirmed via out-of-band callback proof"
	}

	if hasAnyEvidenceValue(ev, "visual_validation", "screenshot", "browser_console", "dom_snapshot", "browser_trace") {
		return proofClassBrowser, "confirmed via browser proof"
	}

	if hasAnyEvidenceValue(ev, "timing_delta", "timing_ms", "response_time_ms", "baseline_timing_ms") {
		return proofClassTiming, "confirmed via timing proof"
	}

	requestCaptured := hasAnyEvidenceValue(ev, "request", "raw_request", "replay_request", "curl")
	responseCaptured := hasAnyEvidenceValue(ev, "response", "raw_response", "response_body", "status_code", "sql_error", "execution_output")
	if requestCaptured && responseCaptured {
		return proofClassRequestResponse, "confirmed via request/response proof"
	}

	return proofClassNone, "missing request/response pair, browser proof, timing proof, or OOB proof"
}

func hasAnyEvidenceValue(evidence map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		if hasEvidenceValue(evidence[key]) {
			return true
		}
	}
	return false
}

func hasEvidenceValue(value interface{}) bool {
	switch v := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(v) != ""
	case bool:
		return v
	case int:
		return v != 0
	case int8:
		return v != 0
	case int16:
		return v != 0
	case int32:
		return v != 0
	case int64:
		return v != 0
	case uint:
		return v != 0
	case uint8:
		return v != 0
	case uint16:
		return v != 0
	case uint32:
		return v != 0
	case uint64:
		return v != 0
	case float32:
		return v != 0
	case float64:
		return v != 0
	default:
		return strings.TrimSpace(fmt.Sprint(v)) != ""
	}
}

func proofRequirementForSpec(specType, context string) string {
	lower := strings.ToLower(context)

	switch normalizeSpecialistName(specType) {
	case "xss", "csti", "openredirect", "visualcrawler":
		return "Browser proof required: preserve a screenshot, DOM mutation, or browser-side execution trace before promotion."
	case "ssrf", "xxe":
		return "Prefer OOB proof. If the issue is non-blind, preserve the exact exploit request and the server response."
	case "rce":
		return "Prefer OOB proof for blind execution. Otherwise preserve the exploit request and the execution response."
	case "sqli", "sqlmap":
		if strings.Contains(lower, "time") || strings.Contains(lower, "blind") || strings.Contains(lower, "sleep") {
			return "Timing proof required: capture the delayed response timing or timing delta before promotion."
		}
		return "Request/response proof required: preserve the exploit request and the differing or erroring response."
	case "authdiscovery", "idor", "apisecurity", "jwt", "businesslogic", "fileupload", "lfi", "header_injection", "protopollution", "wafevasion":
		return "Request/response proof required: preserve the exploit request and the changed authorization or application response."
	default:
		if strings.Contains(lower, "callback") || strings.Contains(lower, "oob") {
			return "OOB proof required: preserve the callback token and interaction details before promotion."
		}
		return "Only promote findings backed by request/response, browser, timing, or OOB proof."
	}
}
