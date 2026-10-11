# Mirage Autonomy Benchmark — Baseline vs Updated

**Date:** 2026-10-11  
**Baseline reference:** Mirage behavior before `ExecutionObserver` (observed on `mirage-v2-hardening` live lab + code paths that marked think-only scans `completed`)  
**Updated branch:** `mirage-autonomy-intel`  
**Targets:** deterministic stubs + DOCUMENTATION-ONLY notes from authorized lab (`http://203.0.113.10/` / compose allowlist). No unauthorized external targets.

## 1. Scenarios

| ID | Scenario | Model | Target | Purpose |
|---|---|---|---|---|
| S1 | Think-only / no scanners | Deterministic `thinkOnlyStub` | `http://203.0.113.10/` | False-completion refusal |
| S2 | Unsupported Codex model | `permanentModelStub` + GuardedProvider | `http://203.0.113.10/` | LLM permanent failure status |
| S3 | Unit observer / report sections | In-process | n/a | Replan + evidence trail presence |
| S4 | Live lab (Phase 1, historical) | Remapped generative model (`gpt-6-luna`) | Authorized compose target | Pipeline smoke; scanners not invoked by model |

## 2. Measured results (automated stubs)

Command:

```bash
go test ./internal/smoke/ -count=1 -run 'AutonomyBenchmark|Observer|UnsupportedModel' -timeout 5m
```

### 2.1 Updated build metrics (`TestAutonomyBenchmarkStubbedScenarios`)

| Metric | Baseline (pre-observer) | Updated (measured) | Notes |
|---|---|---|---|
| Empty assessment refused | No (live flow `7e784808` completed with think/complete_task only) | **Yes** | `IncompleteAssessment` error |
| Security tool allows completion | n/a | **Yes** | `run_security_tool` counted |
| Replan after 3 identical tool failures | No dedicated signal | **Yes** | Observer `ConsumeReplanRequest` |
| Report Evidence Trail section | Absent | **Present** | `GenerateReportWithEvidence` |
| Report Execution Health section | Absent | **Present** | Includes security tool runs |
| Think-only E2E flow status | `completed` (historical) | `failed` | Smoke test |
| Think-only final report HTTP | `200` successful assessment text (historical risk) | `404` | Report gated on success path |
| Unsupported model flow status | Was incorrectly completable before PR #9 | `failed` | `TestUnsupportedModelDoesNotCompleteTheScan` |

### 2.2 Pass/fail gates (this run)

| Test | Result |
|---|---|
| `TestAutonomyBenchmarkStubbedScenarios` | Executed with suite (see CI/local log) |
| `TestObserverRefusesSuccessfulCompletionWithoutScanners` | Pass (suite) |
| `TestUnsupportedModelDoesNotCompleteTheScan` | Pass (suite) |
| `TestObserverDetectsEmptyAssessment` / replan / report unit tests | Pass |

Measured `AUTONOMY_BENCHMARK_METRICS` from `go test ./internal/smoke/ -v -run AutonomyBenchmark` on 2026-10-11:

```json
{
  "e2e_duration_ms": 25751,
  "e2e_report_http_status": 404,
  "e2e_successful_report_blocked": true,
  "e2e_think_only_failed": true,
  "e2e_think_only_status": "failed",
  "empty_assessment_refused": true,
  "replan_after_3_failures": true,
  "replan_reason_nonempty": true,
  "report_has_evidence_trail": true,
  "report_has_execution_health": true,
  "report_lists_evidence_pack": true,
  "report_lists_workspace_artifact": true,
  "security_tool_allows_completion": true
}
```

## 3. Live generative scan (Phase 1 — not a claim of scanner depth)

| Item | Result |
|---|---|
| Dashboard → API → Orchestrator → LLM | Worked after model remap to supported Codex model |
| Execution Gateway → Docker scanners | **Not exercised** — model chose think/complete_task only |
| PostgreSQL / artifacts / report | Flow completed historically; report quality was misleading (0 findings, no scanners) |
| Unauthorized RFC1918 target | Blocked until `MIRAGE_TARGET_ALLOWLIST` set in compose |

**Honest conclusion:** Phase 1 proved LLM path + status fixes. It did **not** prove deep scanner finding quality. Observer on this branch now fails that empty-assessment pattern.

## 4. Metrics not yet measured (expectations, not claims)

| Metric | Expectation | Status |
|---|---|---|
| Valid findings count vs baseline | Neutral/positive on equal scanner runs | Not measured with live scanners on this branch |
| Unsupported/unverified findings rate | Lower when auditor + evidence trail used | Not measured |
| Redundant tool executions | Lower after replan signaling is consumed by planner | Partial (signal emitted; `ShouldReplan` not fully wired) |
| Decision-1 routing overhead | Unchanged (Decision-1 untouched) | Not re-benchmarked |
| LLM call count | Slightly lower via permanent-failure circuit (PR #9) | Qualitatively observed; not cost-metered here |

## 5. Interpretation

- **Measured autonomy reliability win:** false-complete think-only scans are refused; failed scans cannot serve a successful assessment report.
- **Measured observability win:** reports include Evidence Trail + Execution Health when evidence exists.
- **Not claimed:** higher finding counts, faster runtime, or superiority over CyberStrikeAI/LuaN1aoAgent overall.

## 6. Reproduce

```bash
go test ./internal/agent/ -count=1 -run 'Observer|ReportIncludes'
go test ./internal/smoke/ -count=1 -run 'AutonomyBenchmark|Observer|UnsupportedModel' -timeout 5m
go test ./... -count=1
go vet ./...
```
