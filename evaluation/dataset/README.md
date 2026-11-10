# VulnGuard Research Benchmark Dataset (v1.0.0)

## Overview

This dataset provides a curated, balanced benchmark of 30 isolated vulnerability and safe counter-example cases across five major Common Weakness Enumerations (CWEs). It is specifically designed to provide rigorous, ground-truth-validated empirical evaluation for AI vulnerability detection, localization, and automated repair pipelines.

## Composition

| Vulnerability Category | CWE Identifier | Vulnerable Cases | Safe Counter-Examples | Total Cases | Target Languages |
|---|---|---:|---:|---:|---|
| **SQL Injection** | CWE-89 | 3 (`B01`–`B03`) | 3 (`B04`–`B06`) | 6 | Python |
| **Command Injection** | CWE-78 | 3 (`B07`–`B09`) | 3 (`B10`–`B12`) | 6 | Python |
| **Path Traversal** | CWE-22 | 3 (`B13`–`B15`) | 3 (`B16`–`B18`) | 6 | Python, C |
| **Buffer Handling / Memory Safety** | CWE-120 | 3 (`B19`–`B21`) | 3 (`B22`–`B24`) | 6 | C |
| **Format String** | CWE-134 | 3 (`B25`–`B27`) | 3 (`B28`–`B30`) | 6 | C |
| **Total** | | **15** | **15** | **30** | Python, C |

---

## Directory Structure

```text
evaluation/dataset/
├── manifest.csv               # Ground-truth metadata (isolated from target analysis context)
├── README.md                  # This documentation file
├── harness.py                 # Independent execution engine for security and regression tests
├── vulnerable/                # Isolated source fixtures containing genuine flaws
│   ├── sql/                   # sqli_01.py, sqli_02.py, sqli_03.py
│   ├── command/               # cmdi_01.py, cmdi_02.py, cmdi_03.py
│   ├── path/                  # path_01.py, path_02.py, path_03.c
│   ├── memory/                # mem_01.c, mem_02.c, mem_03.c
│   └── format/                # fmt_01.c, fmt_02.c, fmt_03.c
├── safe/                      # Paired safe implementations
│   ├── sql/                   # safe_sql_01.py, safe_sql_02.py, safe_sql_03.py
│   ├── command/               # safe_cmd_01.py, safe_cmd_02.py, safe_cmd_03.py
│   ├── path/                  # safe_path_01.py, safe_path_02.py, safe_path_03.c
│   ├── memory/                # safe_mem_01.c, safe_mem_02.c, safe_mem_03.c
│   └── format/                # safe_fmt_01.c, safe_fmt_02.c, safe_fmt_03.c
└── tests/
    ├── security/              # test_security_all.py
    └── regression/            # test_regression_all.py
```

---

## Isolation and Zero Leakage Guarantee

1. **Separation of Concerns:** The source fixtures inside `vulnerable/` and `safe/` contain solely raw program logic. They do NOT contain ground-truth labels, expected exploit payloads, reference patches, or assertions.
2. **Analysis Context:** During evaluation, VulnGuard is provided ONLY with the target source file path inside an isolated workspace. It is given zero access to `manifest.csv`, `harness.py`, or test suites.
3. **Independent Oracle:** Exploit validation and functional regression tests are executed externally by `evaluation/dataset/harness.py`. Neither the Red Agent nor the Blue Agent nor the Judge Agent has authority over ground-truth verification.

---

## Verification Commands

Validate manifest and fixture integrity:
```bash
python -m evaluation.scripts.validate_dataset
```

Independently execute all ground-truth security and regression tests:
```bash
python -m evaluation.scripts.validate_benchmark
```

