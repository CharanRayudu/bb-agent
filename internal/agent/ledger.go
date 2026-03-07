package agent

import (
	"fmt"
	"log"
	"strings"

	"github.com/bb-agent/mirage/internal/database"
	"github.com/bb-agent/mirage/internal/models"
	"github.com/google/uuid"
)

func (o *Orchestrator) createLedgerSubTask(
	taskID uuid.UUID,
	parentSubTaskID *uuid.UUID,
	name string,
	description string,
	agentType models.AgentType,
	kind models.SubTaskKind,
	queueName string,
	target string,
	priority string,
	fingerprint string,
	context string,
	metadata map[string]any,
) (*models.SubTask, error) {
	if o.queries == nil {
		return &models.SubTask{
			ID:              uuid.New(),
			TaskID:          taskID,
			ParentSubTaskID: parentSubTaskID,
			Name:            name,
			Description:     description,
			Status:          models.SubTaskStatusQueued,
			AgentType:       agentType,
			Context:         context,
			Kind:            kind,
			QueueName:       queueName,
			Target:          target,
			Priority:        priority,
			Fingerprint:     fingerprint,
			Outcome:         models.SubTaskOutcomePending,
			Metadata:        metadata,
		}, nil
	}

	return o.queries.CreateSubTaskWithOptions(taskID, name, description, agentType, database.SubTaskCreateOptions{
		ParentSubTaskID: parentSubTaskID,
		Context:         context,
		Kind:            kind,
		QueueName:       queueName,
		Target:          target,
		Priority:        priority,
		Fingerprint:     fingerprint,
		Outcome:         models.SubTaskOutcomePending,
		Metadata:        metadata,
	})
}

func (o *Orchestrator) updateLedgerSubTask(
	subtaskID uuid.UUID,
	status models.SubTaskStatus,
	result string,
	outcome models.SubTaskOutcome,
	metadata map[string]any,
) {
	if o.queries == nil || subtaskID == uuid.Nil {
		return
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	if err := o.queries.UpdateSubTaskState(subtaskID, status, result, outcome, metadata); err != nil {
		log.Printf("[ledger] failed to update subtask %s: %v", subtaskID, err)
	}
}

func evidenceSummary(f *Finding, fallback string) string {
	if f == nil {
		return strings.TrimSpace(fallback)
	}
	parts := []string{strings.TrimSpace(f.Type), strings.TrimSpace(f.URL)}
	if f.Parameter != "" {
		parts = append(parts, fmt.Sprintf("param %s", f.Parameter))
	}
	if strings.TrimSpace(fallback) != "" {
		parts = append(parts, strings.TrimSpace(fallback))
	}
	return strings.Join(parts, " | ")
}

func buildEvidenceProof(f *Finding, summary string) map[string]any {
	proofClass, proofReason := classifyFindingProof(f)
	proof := map[string]any{
		"summary":      strings.TrimSpace(summary),
		"proof_reason": proofReason,
	}
	if proofClass != proofClassNone {
		proof["proof_class"] = string(proofClass)
	}
	if f == nil {
		return proof
	}
	if f.Payload != "" {
		proof["payload"] = f.Payload
	}
	if f.Method != "" {
		proof["method"] = f.Method
	}
	if artifacts := buildEvidenceArtifacts(f); len(artifacts) > 0 {
		proof["artifacts"] = artifacts
	}
	if len(f.Evidence) > 0 {
		proof["evidence"] = f.Evidence
	}
	return proof
}

func (o *Orchestrator) recordEvidencePack(
	flowID uuid.UUID,
	taskID *uuid.UUID,
	subtaskID *uuid.UUID,
	f *Finding,
	status models.EvidenceStatus,
	summary string,
) {
	if o.queries == nil || f == nil {
		return
	}

	pack := &models.EvidencePack{
		FlowID:      flowID,
		TaskID:      taskID,
		SubTaskID:   subtaskID,
		Fingerprint: findingFingerprint(f),
		Status:      status,
		Type:        f.Type,
		URL:         f.URL,
		Parameter:   f.Parameter,
		Payload:     f.Payload,
		Severity:    f.Severity,
		Confidence:  f.Confidence,
		Summary:     evidenceSummary(f, summary),
		SourceAgent: f.Agent,
		Proof:       buildEvidenceProof(f, summary),
	}

	if err := o.queries.UpsertEvidencePack(pack); err != nil {
		log.Printf("[ledger] failed to persist evidence pack for %s: %v", pack.Fingerprint, err)
	}
}

func (o *Orchestrator) recordHypothesisPack(
	flowID uuid.UUID,
	taskID uuid.UUID,
	subtaskID *uuid.UUID,
	spec SwarmAgentSpec,
	baseTarget string,
) {
	if o.queries == nil {
		return
	}

	fingerprint := dispatchFingerprint(spec, baseTarget)
	resolvedTarget := resolveDispatchTarget(baseTarget, spec.Target)
	summary := strings.TrimSpace(spec.Hypothesis)
	if summary == "" {
		summary = defaultHypothesis(spec, baseTarget)
	}

	pack := &models.EvidencePack{
		FlowID:      flowID,
		TaskID:      &taskID,
		SubTaskID:   subtaskID,
		Fingerprint: fingerprint,
		Status:      models.EvidenceStatusHypothesis,
		Type:        spec.Type,
		URL:         resolvedTarget,
		Severity:    normalizePriority(spec.Priority),
		Confidence:  0.35,
		Summary:     summary,
		SourceAgent: "planner",
		Proof: map[string]any{
			"hypothesis":        summary,
			"proof_requirement": spec.Proof,
			"requires_auth":     spec.RequiresAuth,
			"auth_context":      spec.AuthContext,
			"attack_graph_node": attackGraphNodeID("hypothesis", fingerprint),
			"context":           spec.Context,
			"dispatch_target":   resolvedTarget,
			"priority":          normalizePriority(spec.Priority),
		},
	}

	if err := o.queries.UpsertEvidencePack(pack); err != nil {
		log.Printf("[ledger] failed to persist hypothesis pack for %s: %v", fingerprint, err)
	}
}

func subtaskIDFromFinding(f *Finding) *uuid.UUID {
	if f == nil || strings.TrimSpace(f.SubTaskID) == "" {
		return nil
	}
	parsed, err := uuid.Parse(strings.TrimSpace(f.SubTaskID))
	if err != nil {
		return nil
	}
	return &parsed
}

func outcomeForLoopResult(result string) (models.SubTaskStatus, models.SubTaskOutcome) {
	lower := strings.ToLower(strings.TrimSpace(result))
	switch {
	case lower == "", lower == "max iterations reached":
		return models.SubTaskStatusCompleted, models.SubTaskOutcomeExhausted
	case strings.HasPrefix(lower, "cancelled"):
		return models.SubTaskStatusFailed, models.SubTaskOutcomeBlockedByRuntime
	case strings.HasPrefix(lower, "error:"):
		return models.SubTaskStatusFailed, models.SubTaskOutcomeBlockedByRuntime
	case strings.Contains(lower, "victory hierarchy"):
		return models.SubTaskStatusCompleted, models.SubTaskOutcomeConfirmed
	default:
		return models.SubTaskStatusCompleted, models.SubTaskOutcomeCompleted
	}
}
