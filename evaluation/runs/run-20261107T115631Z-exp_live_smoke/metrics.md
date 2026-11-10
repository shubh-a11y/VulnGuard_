# Research Evaluation Metric Summary: run-20261107T115631Z-exp_live_smoke

**Evaluated Cases:** 2 total (2 vulnerable, 0 safe controls, 2 eligible)

| Metric Name | Formula | Numerator / Denominator | Calculated Value | 95% Confidence Interval | Status |
|---|---|---:|---:|---:|:---:|
| **Detection Rate (DR)** | `vulnerabilities_detected / eligible_vulnerable_cases` | 2 / 2 | **100.0%** | [34.24%, 100.0%] | `measured` |
| **CWE Classification Accuracy** | `correct_cwe_predictions / vulnerabilities_detected` | 2 / 2 | **100.0%** | [34.24%, 100.0%] | `measured` |
| **Localization Accuracy** | `correctly_localized_cases / vulnerabilities_detected` | 2 / 2 | **100.0%** | [34.24%, 100.0%] | `measured` |
| **Patch Success Rate @ 1 (PSR@1)** | `strictly_accepted_repairs_attempt_1 / eligible_vulnerable_cases` | 0 / 2 | **0.0%** | [0.0%, 65.76%] | `measured` |
| **Patch Success Rate @ 3 (PSR@3)** | `strictly_accepted_repairs_within_3_attempts / eligible_vulnerable_cases` | 0 / 2 | **0.0%** | [0.0%, 65.76%] | `measured` |
| **Application Success Rate (ASR)** | `successfully_applied_patches / patch_application_attempts` | 1 / 1 | **100.0%** | [20.65%, 100.0%] | `measured` |
| **Exploit Blocking Rate (EBR)** | `exploits_blocked_after_patching / applied_patches_tested` | 1 / 1 | **100.0%** | [20.65%, 100.0%] | `measured` |
| **Regression Rate (RR)** | `regression_failures_after_patching / applied_patches_tested` | 1 / 1 | **100.0%** | [20.65%, 100.0%] | `measured` |
| **Malformed Patch Rate** | `malformed_or_invalid_syntax_patches / patches_generated` | 0 / 1 | **0.0%** | [0.0%, 79.35%] | `measured` |
| **Retry Recovery Rate** | `repairs_recovered_via_retries / cases_needing_retry` | 0 / 2 | **0.0%** | [0.0%, 65.76%] | `measured` |

## Resource and Cost Footprint

- **Total LLM Calls:** 16
- **Total Tokens:** 41,043 (Prompt: 17,224, Completion: 23,819)
- **Total Estimated Cost:** $0.0000
- **Cost Per Case:** $0.0000
- **Mean Latency:** 145.56 s (Median: 145.56 s, P95: 181.15 s)

## Strict Repair Failure Breakdown

| Failure Category | Case Count |
|---|---:|
| `REGRESSION_FAILURE` | 1 |
| `BLUE_GENERATION_FAILURE` | 1 |