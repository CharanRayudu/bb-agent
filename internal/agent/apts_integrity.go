package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// EvidenceBundle is the canonical structure hashed for APTS AR integrity binding.
// APTS Domain 5 (Auditability): every finding must have a tamper-evident SHA-256 hash.
type EvidenceBundle struct {
	Type        string    `json:"type"`
	URL         string    `json:"url"`
	Parameter   string    `json:"parameter,omitempty"`
	Payload     string    `json:"payload,omitempty"`
	Severity    string    `json:"severity"`
	ProofType   string    `json:"proof_type"`
	Request     string    `json:"request,omitempty"`
	Response    string    `json:"response,omitempty"`
	OOBCallback string    `json:"oob_callback,omitempty"`
	Screenshot  string    `json:"screenshot,omitempty"`
	TimingDelta string    `json:"timing_delta,omitempty"`
	Agent       string    `json:"agent,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// ComputeEvidenceHash computes a SHA-256 integrity hash for a finding's evidence bundle.
// This hash binds the raw technical evidence to the finding record, satisfying
// APTS AR requirements for cryptographic evidence integrity.
func ComputeEvidenceHash(f *Finding) string {
	bundle := extractEvidenceBundle(f)
	data, err := json.Marshal(bundle)
	if err != nil {
		// Fallback: hash the finding URL + type + timestamp
		fallback := fmt.Sprintf("%s|%s|%s", f.Type, f.URL, f.Timestamp.Format(time.RFC3339))
		h := sha256.Sum256([]byte(fallback))
		return hex.EncodeToString(h[:])
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// extractEvidenceBundle builds an EvidenceBundle from a Finding's evidence map.
func extractEvidenceBundle(f *Finding) EvidenceBundle {
	b := EvidenceBundle{
		Type:      f.Type,
		URL:       f.URL,
		Parameter: f.Parameter,
		Payload:   f.Payload,
		Severity:  f.Severity,
		Agent:     f.Agent,
		Timestamp: f.Timestamp,
	}

	proof, _ := classifyFindingProof(f)
	b.ProofType = string(proof)

	if f.Evidence != nil {
		if v, ok := f.Evidence["request"].(string); ok {
			b.Request = v
		}
		if v, ok := f.Evidence["response"].(string); ok {
			b.Response = v
		}
		if v, ok := f.Evidence["oob_callback"].(string); ok {
			b.OOBCallback = v
		}
		if v, ok := f.Evidence["screenshot"].(string); ok {
			b.Screenshot = v
		}
		if v, ok := f.Evidence["timing_delta"].(string); ok {
			b.TimingDelta = v
		}
	}

	return b
}

// VerifyEvidenceHash re-computes and checks the hash stored on a Finding.
// Returns true if the evidence has not been tampered with.
func VerifyEvidenceHash(f *Finding, storedHash string) bool {
	computed := ComputeEvidenceHash(f)
	return computed == storedHash
}
