#!/usr/bin/env bash
# Sequential live evaluation of the documented labeled cohort.
# Sequential on purpose: data/llm_usage.jsonl is a single append-only log, so
# concurrent runs would make per-case token/cost attribution ambiguous.
set -u
cd "$(dirname "$0")/../../.." || exit 1
echo "project root: $(pwd)"

OUT=evaluation/run-2026-10-28T-baseline
PY=.venv/Scripts/python.exe
mkdir -p "$OUT/logs" "$OUT/cases"

run () {
  local cid="$1"; local rel="$2"; local fn="$3"
  echo "=== $cid $rel:$fn start $(date -Iseconds) ==="
  $PY "$OUT/procedure/run_case.py" --case-id "$cid" --rel-path "$rel" \
      --function "$fn" --out "$OUT/cases" 2>&1 \
    | grep -v "LiteLLM:WARNING" | grep -v "UserWarning\|save_model\|difference\|readthedocs\|setstate\|^$" \
    | tee -a "$OUT/logs/05-cases.log"
  echo "=== $cid end $(date -Iseconds) ==="
}

run C02 data/test_vulns/vuln_cmdi.py    ping_host
run C03 data/test_vulns/vuln_buffer.c   process_data
run C04 data/test_vulns/vuln_format.c   log_message
run C05 data/test_vulns/vuln_race.c     write_secure_log
run C06 data/test_vulns/vuln_taint_flow/input_handler.py handle_request
echo "ALL DONE $(date -Iseconds)"
