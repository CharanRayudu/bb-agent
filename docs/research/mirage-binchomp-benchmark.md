# Mirage BinChomp-inspired Validation Benchmark

**Date:** 2026-10-11  
**Branch:** `mirage-binchomp-validation`  
**Method:** Deterministic synthetic findings + stub Reflector LLM failures. No unauthorized targets.

## Measured results

Command:

```bash
go test ./internal/agent/ -count=1 -run 'VerifyFinding|PartitionFindings|ReflectorValidate|ReportIncludesVerification'
go test ./internal/smoke/ -count=1 -v -run BinChompValidationBenchmark
```

| Metric | Baseline (pre-change) | Updated (required) |
|---|---|---|
| Reflector on LLM error | Auto-accept (`true`) | Fail-closed (`false`) |
| Unproven finding in detailed report | Could appear as finding | Partitioned to needs_proof/hypothesis |
| Confirmed-only report body | Not enforced | `ConfirmedFindings()` only |
| Environment snapshot in report | Absent | Present (`## Environment Snapshot`) |

Measured `BINCHOMP_VALIDATION_METRICS` (2026-10-11):

```json
{
  "env_snapshot_has_go": true,
  "reflector_fail_closed": true,
  "report_confirmed_only": true,
  "unverified_needs_proof_or_hypothesis": 1,
  "validated_confirmed": 1
}
```

Live generative scanner depth is **not** claimed here.
