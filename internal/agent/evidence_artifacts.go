package agent

import "strings"

func buildEvidenceArtifacts(f *Finding) []map[string]any {
	if f == nil || len(f.Evidence) == 0 {
		return nil
	}

	evidence := f.Evidence
	artifacts := make([]map[string]any, 0, 4)

	if key, value, ok := firstEvidenceValue(evidence, "request", "raw_request", "http_request", "replay_request", "curl"); ok {
		metadata := collectEvidenceMetadata(evidence, "request_headers", "request_body")
		if strings.TrimSpace(f.Method) != "" {
			metadata["method"] = f.Method
		}
		if strings.TrimSpace(f.URL) != "" {
			metadata["url"] = f.URL
		}
		if strings.TrimSpace(f.Parameter) != "" {
			metadata["parameter"] = f.Parameter
		}
		artifacts = append(artifacts, evidenceArtifact("http_request", "Exploit request", key, value, metadata))
	}

	if key, value, ok := firstEvidenceValue(evidence, "response", "raw_response", "http_response", "response_body", "sql_error", "execution_output"); ok {
		metadata := collectEvidenceMetadata(evidence, "response_headers", "response_body", "status_code")
		artifacts = append(artifacts, evidenceArtifact("http_response", "Exploit response", key, value, metadata))
	}

	if key, value, ok := firstEvidenceValue(evidence, "visual_validation", "screenshot", "browser_console", "dom_snapshot", "browser_trace"); ok {
		metadata := collectEvidenceMetadata(evidence, "screenshot", "browser_console", "dom_snapshot", "browser_trace")
		artifacts = append(artifacts, evidenceArtifact("browser", "Browser proof", key, value, metadata))
	}

	if key, value, ok := firstEvidenceValue(evidence, "timing_delta", "timing_ms", "response_time_ms", "baseline_timing_ms"); ok {
		metadata := collectEvidenceMetadata(evidence, "timing_delta", "timing_ms", "response_time_ms", "baseline_timing_ms")
		artifacts = append(artifacts, evidenceArtifact("timing", "Timing proof", key, value, metadata))
	}

	if key, value, ok := firstEvidenceValue(evidence, "oob_type", "oob_remote", "oob_token", "callback", "oob_raw_data"); ok {
		metadata := collectEvidenceMetadata(evidence, "oob_type", "oob_remote", "oob_token", "callback", "oob_raw_data")
		artifacts = append(artifacts, evidenceArtifact("oob", "Out-of-band proof", key, value, metadata))
	}

	return artifacts
}

func evidenceArtifact(artifactType, label, sourceKey string, value any, metadata map[string]any) map[string]any {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["source_key"] = sourceKey

	artifact := map[string]any{
		"type":     artifactType,
		"label":    label,
		"metadata": metadata,
	}
	if content, ok := value.(string); ok {
		artifact["content"] = strings.TrimSpace(content)
	} else {
		artifact["content"] = value
	}
	return artifact
}

func collectEvidenceMetadata(evidence map[string]interface{}, keys ...string) map[string]any {
	metadata := map[string]any{}
	for _, key := range keys {
		value, ok := evidence[key]
		if !ok || !hasEvidenceValue(value) {
			continue
		}
		metadata[key] = value
	}
	return metadata
}

func firstEvidenceValue(evidence map[string]interface{}, keys ...string) (string, any, bool) {
	for _, key := range keys {
		value, ok := evidence[key]
		if !ok || !hasEvidenceValue(value) {
			continue
		}
		return key, value, true
	}
	return "", nil, false
}
