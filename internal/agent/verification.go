package agent

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/llm"
	"github.com/bb-agent/mirage/internal/models"
)

// VerificationStatus is a deterministic (non-LLM) claim classification.
// Inspired by BinChomp's external verification oracles: the model cannot
// self-certify a finding without durable proof classes.
type VerificationStatus string

const (
	VerificationConfirmed    VerificationStatus = "confirmed"
	VerificationNeedsProof   VerificationStatus = "needs_proof"
	VerificationHypothesis   VerificationStatus = "hypothesis"
	VerificationRejected     VerificationStatus = "rejected"
	VerificationInconclusive VerificationStatus = "inconclusive"
)

// VerifiedFinding is one finding after the deterministic oracle runs.
type VerifiedFinding struct {
	Finding    *Finding
	Status     VerificationStatus
	ProofClass string
	Reason     string
}

// VerificationPartition separates demonstrated claims from unverified ones.
type VerificationPartition struct {
	Confirmed    []VerifiedFinding
	NeedsProof   []VerifiedFinding
	Hypothesis   []VerifiedFinding
	Rejected     []VerifiedFinding
	Inconclusive []VerifiedFinding
}

// Counts returns roll-up metrics for benchmarks and reports.
func (p VerificationPartition) Counts() map[string]int {
	return map[string]int{
		"confirmed":    len(p.Confirmed),
		"needs_proof":  len(p.NeedsProof),
		"hypothesis":   len(p.Hypothesis),
		"rejected":     len(p.Rejected),
		"inconclusive": len(p.Inconclusive),
		"total_inputs": len(p.Confirmed) + len(p.NeedsProof) + len(p.Hypothesis) + len(p.Rejected) + len(p.Inconclusive),
	}
}

// ConfirmedFindings returns only findings that passed the deterministic oracle.
func (p VerificationPartition) ConfirmedFindings() []*Finding {
	out := make([]*Finding, 0, len(p.Confirmed))
	for _, v := range p.Confirmed {
		out = append(out, v.Finding)
	}
	return out
}

// VerifyFindingDeterministic classifies a finding without calling an LLM.
func VerifyFindingDeterministic(f *Finding) VerifiedFinding {
	if f == nil {
		return VerifiedFinding{Status: VerificationInconclusive, Reason: "finding is nil"}
	}
	if err := ValidateFinding(f); err != nil {
		return VerifiedFinding{Finding: f, Status: VerificationRejected, Reason: err.Error()}
	}
	proof, reason := classifyFindingProof(f)
	if proof == proofClassNone {
		status := VerificationNeedsProof
		if strings.TrimSpace(f.Payload) == "" && len(f.Evidence) == 0 {
			status = VerificationHypothesis
		}
		return VerifiedFinding{Finding: f, Status: status, Reason: reason}
	}
	if f.Confidence > 0 && f.Confidence < 0.8 {
		return VerifiedFinding{
			Finding:    f,
			Status:     VerificationNeedsProof,
			ProofClass: string(proof),
			Reason:     fmt.Sprintf("confidence %.2f below confirmation threshold for %s proof", f.Confidence, proof),
		}
	}
	return VerifiedFinding{
		Finding:    f,
		Status:     VerificationConfirmed,
		ProofClass: string(proof),
		Reason:     reason,
	}
}

// PartitionFindingsForReport applies the deterministic oracle and optional pack statuses.
func PartitionFindingsForReport(findings []*Finding, packs []models.EvidencePack) VerificationPartition {
	packStatus := map[string]models.EvidenceStatus{}
	for _, pack := range packs {
		key := strings.ToLower(strings.TrimSpace(pack.Fingerprint))
		if key == "" {
			key = strings.ToLower(fmt.Sprintf("%s|%s|%s", pack.Type, pack.URL, pack.Parameter))
		}
		packStatus[key] = pack.Status
		if pack.Type != "" && pack.URL != "" {
			packStatus[strings.ToLower(fmt.Sprintf("%s|%s", pack.Type, pack.URL))] = pack.Status
		}
	}

	var part VerificationPartition
	for _, f := range findings {
		v := VerifyFindingDeterministic(f)
		if f != nil {
			fp := strings.ToLower(findingFingerprint(f))
			if st, ok := packStatus[fp]; ok {
				switch st {
				case models.EvidenceStatusRejected:
					v.Status = VerificationRejected
					v.Reason = "evidence pack rejected"
				case models.EvidenceStatusHypothesis:
					if v.Status == VerificationConfirmed {
						// Keep confirmed when durable proof exists; pack may lag.
					} else {
						v.Status = VerificationHypothesis
						v.Reason = "evidence pack still hypothesis"
					}
				case models.EvidenceStatusNeedsProof:
					if v.Status == VerificationConfirmed {
						v.Status = VerificationNeedsProof
						v.Reason = "evidence pack requires additional proof"
					}
				case models.EvidenceStatusConfirmed:
					if v.Status == VerificationNeedsProof || v.Status == VerificationHypothesis {
						// Pack claims confirmed but oracle disagrees — keep oracle (non-LLM) result.
						v.Reason = v.Reason + "; pack marked confirmed but deterministic proof incomplete"
					}
				}
			}
		}
		switch v.Status {
		case VerificationConfirmed:
			part.Confirmed = append(part.Confirmed, v)
		case VerificationNeedsProof:
			part.NeedsProof = append(part.NeedsProof, v)
		case VerificationHypothesis:
			part.Hypothesis = append(part.Hypothesis, v)
		case VerificationRejected:
			part.Rejected = append(part.Rejected, v)
		default:
			part.Inconclusive = append(part.Inconclusive, v)
		}
	}
	return part
}

// EnvironmentSnapshot records reproducible assessment context (not kernel exploit env).
type EnvironmentSnapshot struct {
	CapturedAt      time.Time `json:"captured_at"`
	GoVersion       string    `json:"go_version"`
	SandboxImage    string    `json:"sandbox_image,omitempty"`
	LLMProvider     string    `json:"llm_provider,omitempty"`
	LLMModel        string    `json:"llm_model,omitempty"`
	LLMSource       string    `json:"llm_source,omitempty"`
	ExecutionV2     string    `json:"execution_v2,omitempty"`
	TargetAllowlist string    `json:"target_allowlist,omitempty"`
}

// CaptureEnvironmentSnapshot gathers process/env metadata for report reproducibility.
func CaptureEnvironmentSnapshot(provider llm.Provider) EnvironmentSnapshot {
	snap := EnvironmentSnapshot{
		CapturedAt:      time.Now().UTC(),
		GoVersion:       runtime.Version(),
		SandboxImage:    firstNonEmpty(os.Getenv("MIRAGE_SANDBOX_IMAGE"), os.Getenv("SANDBOX_IMAGE")),
		LLMModel:        firstNonEmpty(os.Getenv("OPENAI_MODEL"), os.Getenv("MIRAGE_OPENAI_MODEL")),
		LLMSource:       os.Getenv("MIRAGE_LLM_PROVIDER"),
		ExecutionV2:     os.Getenv("MIRAGE_EXECUTION_V2"),
		TargetAllowlist: os.Getenv("MIRAGE_TARGET_ALLOWLIST"),
	}
	if provider != nil {
		snap.LLMProvider = provider.Name()
	}
	if sel, ok := provider.(interface{ Selection() llm.Selection }); ok {
		s := sel.Selection()
		if s.Model != "" {
			snap.LLMModel = s.Model
		}
		if s.Source != "" {
			snap.LLMSource = s.Source
		}
	}
	return snap
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
