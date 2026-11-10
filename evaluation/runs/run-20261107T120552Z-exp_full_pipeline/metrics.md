# Research Evaluation Metric Summary: run-20261107T120552Z-exp_full_pipeline

**Evaluated Cases:** 15 total (15 vulnerable, 0 safe controls, 15 eligible)

| Metric Name | Formula | Numerator / Denominator | Calculated Value | 95% Confidence Interval | Status |
|---|---|---:|---:|---:|:---:|
| **Detection Rate (DR)** | `vulnerabilities_detected / eligible_vulnerable_cases` | 12 / 15 | **80.0%** | [54.81%, 92.95%] | `measured` |
| **CWE Classification Accuracy** | `correct_cwe_predictions / vulnerabilities_detected` | 11 / 12 | **91.67%** | [64.61%, 98.51%] | `measured` |
| **Localization Accuracy** | `correctly_localized_cases / vulnerabilities_detected` | 12 / 12 | **100.0%** | [75.75%, 100.0%] | `measured` |
| **Patch Success Rate @ 1 (PSR@1)** | `strictly_accepted_repairs_attempt_1 / eligible_vulnerable_cases` | 0 / 15 | **0.0%** | [0.0%, 20.39%] | `measured` |
| **Patch Success Rate @ 3 (PSR@3)** | `strictly_accepted_repairs_within_3_attempts / eligible_vulnerable_cases` | 0 / 15 | **0.0%** | [0.0%, 20.39%] | `measured` |
| **Application Success Rate (ASR)** | `successfully_applied_patches / patch_application_attempts` | 12 / 12 | **100.0%** | [75.75%, 100.0%] | `measured` |
| **Exploit Blocking Rate (EBR)** | `exploits_blocked_after_patching / applied_patches_tested` | 12 / 12 | **100.0%** | [75.75%, 100.0%] | `measured` |
| **Regression Rate (RR)** | `regression_failures_after_patching / applied_patches_tested` | 12 / 12 | **100.0%** | [75.75%, 100.0%] | `measured` |
| **Malformed Patch Rate** | `malformed_or_invalid_syntax_patches / patches_generated` | 0 / 12 | **0.0%** | [0.0%, 24.25%] | `measured` |
| **Retry Recovery Rate** | `repairs_recovered_via_retries / cases_needing_retry` | 0 / 15 | **0.0%** | [0.0%, 20.39%] | `measured` |

## Resource and Cost Footprint

- **Total LLM Calls:** 67
- **Total Tokens:** 222,095 (Prompt: 79,512, Completion: 142,583)
- **Total Estimated Cost:** $0.0000
- **Cost Per Case:** $0.0000
- **Mean Latency:** 104.03 s (Median: 81.87 s, P95: 192.21 s)

## Strict Repair Failure Breakdown

| Failure Category | Case Count |
|---|---:|
| `REGRESSION_FAILURE` | 11 |
| `TRIAGE_FILTERED` | 3 |
| `INCORRECT_CWE_CLASSIFICATION` | 1 |