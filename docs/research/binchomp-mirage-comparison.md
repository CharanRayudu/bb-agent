# BinChomp → Mirage v2: Research Comparison and Validation Upgrade

**Date:** 2026-10-11  
**Feature branch:** `mirage-binchomp-validation`  
**Beautiful.ai player:** https://www.beautiful.ai/player/-P2q0r-B7nGYGGK3-32Z/Binchomp-N-Day-Pipeline-Pres  

## 1. Source access limitation (slides)

| Attempt | Result |
|---|---|
| Beautiful.ai player via fetch | Title only (`Binchomp N-Day Pipeline Pres`); body text empty (JS SPA). Preview image available; slide body not extractable. |
| TinyFish browser automation | Request blocked by usage policy; run not retried. |
| Official PDF / slide export | Not found via public search. |
| Conference abstract | [BSides Canberra 2026 talk](https://cfp.bsidescbr.com.au/bsides-canberra-2026/talk/TFBH8S/) — abstract only: “technical look into BinChomp… Windows Kernel.” |

**Therefore:** No per-slide claims are made. Technical claims below are attributed to **verified secondary sources** (author interview transcript + talk metadata), not invented slide content.

### Verified secondary sources

1. **Three Buddy Problem podcast transcript** (OAIC), lightly edited Google Doc export:  
   https://docs.google.com/document/d/1b-8J4ptCzFrNonXJwplyqETPbykOVGGDOrWGUdPmgqE/export?format=txt  
   Episode page: https://securityconversations.fireside.fm/valentina-palmiotti-chompie-vulnpocalypse-matching-mythos  
   Author: Valentina Palmiotti (chompie), IBM X-Force Offensive Research. She states she “released the slides” for the autonomous n-day Windows kernel pipeline (timestamp section *10:31 Self-verification…*).

2. **Talk listing:** BSides Canberra 2026 / [un]prompted.au “BinChomp — autonomous n-day exploit generation pipeline”.

## 2. Extracted methodology (transcript-backed)

| Topic | Finding | Source anchor |
|---|---|---|
| System architecture | Autonomous n-day pipeline for Windows kernel; LLM finds/steers; harness imposes constraints | Transcript §4 (10:31) |
| Agent responsibilities | Model constructs primitives/programs; separate non-model verifier scripts act as oracle | Transcript §4 |
| Research workflow | Bug discovery → dynamic reachability → corruption demo → multi-step verified primitives → chain libraries | Transcript §4–5, §8 |
| Task planning / orchestration | Multi-step pipeline with 4–5 verification gates; long runs can “lose the plot” without gates | Transcript §3–4 |
| Knowledge retrieval | Models biased to public techniques; sparse techniques underrepresented | Transcript §7 |
| Environment preparation | Unprivileged-user harness for LPE; custom MCP/debugger state handling for WinDbg | Transcript §4, §8 |
| Automated validation | **Deterministic external verification** (not model-led); e.g. magic value 1337→1336 for decrement primitive | Transcript §4 |
| Error recovery / iteration | Hallucinated branch invalidates downstream work; must discard and re-verify | Transcript §3 |
| Evidence / reproducibility | Dynamic repro preferred over static reasoning; repro metrics reported vs Mythos dataset | Transcript §5 |
| Evaluation | Reproduced 17/21 bugs; 6 full chains vs Mythos 8; ~$180/chain vs ~$2000 cited | Transcript §5 |
| Limitations | Guardrails on stronger models; debugger clumsiness; hard 5% cases; kernel-specific tooling | Transcript §5, §8 |
| Out of Mirage scope | Kernel exploit weaponization, arbitrary decrement primitives, exploit library chaining | Explicit project constraint |

## 3. Mirage implementation (inspected)

| Area | Mirage location | Status before this branch |
|---|---|---|
| Orchestrator | `internal/agent/orchestrator.go` | Implemented |
| Specialists | `internal/agents/*` | Implemented |
| Ledger / EvidencePack | `internal/models/ledger.go`, `ledger.go`, DB queries | Implemented |
| Causal graph | `attack_graph.go`, brain snapshots | Partial |
| RAG / knowledge | `internal/knowledge` | Implemented |
| Decision-1 | `route.go` | Implemented (non-generative) |
| LLM provider mgmt | `internal/llm/*` (PR #9) | Implemented |
| Docker gateway | `internal/execution`, `internal/docker` | Implemented |
| Workspace artifacts | DB + orchestrator save | Implemented |
| Finding verification | `proof.go`, `shouldPromoteFinding`, Skeptic, Reflector | Partial — Reflector **fail-open** on LLM error |
| Reports | `reporter.go` evidence trail (PR #10) | Partial — did not partition confirmed vs unverified |
| Observer | `observer.go` (PR #10) | Implemented (empty assessment veto) |
| Env provenance | APTS static tool list | Missing per-assessment snapshot in reports |

## 4. Comparison table

| Research concept | Verified source | Mirage implementation | Confirmed gap | Recommendation |
|---|---|---|---|---|
| Deterministic external verification oracle | Transcript §4 (non-model script checks) | `classifyFindingProof` / `shouldPromoteFinding` | **Partial** — Reflector auto-accepted on LLM failure | Fail-closed Reflector + report-time deterministic partition |
| Multi-step verification gates | Transcript §4 (4–5 steps) | EvidenceStatusHypothesis→NeedsProof→Confirmed | Partial | Keep statuses; enforce in reports |
| Dynamic reachability before accept | Transcript §4 | Web proof classes (RR/browser/timing/OOB) | Partial (web-adapted) | Do not port kernel reachability |
| Unprivileged / constrained env | Transcript §4 | Docker sandbox + allowlist + gateway | Implemented (different domain) | Keep; add env snapshot |
| Discard work after hallucinated branch | Transcript §3 | Observer replan signal; fatal LLM abort | Partial | Already improved in PR #9/#10 |
| Repro metrics / evaluation harness | Transcript §5 | Smoke/autonomy benchmarks | Partial | Add validation benchmark |
| Independent observer | (related Chinese-AI work; BinChomp emphasizes harness oracles) | `ExecutionObserver` | Already addressed in PR #10 | Reuse |
| Kernel exploit generation | Talk abstract + transcript | n/a | **Not applicable** | Do not implement |
| Exploit primitive libraries | Transcript §8 | n/a | **Not applicable** | Do not implement |
| Environment reproducibility metadata | Implied by dynamic repro / tooling work | Static APTS provenance only | **Missing** | Environment Snapshot in reports |
| Report distinguishes demonstrated vs claimed | Transcript emphasis on prove-before-accept | Leads vs findings; trail refs | **Partial** | Verification Status section; confirmed-only detailed findings |

## 5. Prioritization and selection (≤2)

| Rank | Gap | Impact | Complexity | Decision |
|---|---|---|---|---|
| 1 | Deterministic verification + fail-closed Reflector | High (assessment correctness) | Low–medium | **Implement** |
| 2 | Environment snapshot in reports | Medium (reproducibility) | Low | **Implement** |
| 3 | Wire `ShouldReplan`/`CreatePlan` | Medium | Higher | Defer |
| 4 | Kernel exploit / weaponization | n/a | n/a | Reject |

## 6. Implementation summary (this branch)

1. **`internal/agent/verification.go`** — non-LLM oracle `VerifyFindingDeterministic` / `PartitionFindingsForReport`; `CaptureEnvironmentSnapshot`.
2. **`reflector.go`** — LLM failure → reject (`deterministic proof required`), not auto-accept.
3. **`orchestrator.go`** — OOB findings through `shouldPromoteFinding`; report uses confirmed-only findings + verification partition + env snapshot.
4. **`reporter.go`** — `## Verification Status` and `## Environment Snapshot`.
5. Tests: `verification_test.go`, `binchomp_benchmark_test.go`.

## 7. What was intentionally not built

- Windows kernel exploitation, privilege-escalation payloads, attack-chain deployment.
- Copying BinChomp’s exploit libraries or magic-value memory oracles.
- Architectural rewrite of orchestrator / Decision-1 / scanners.
