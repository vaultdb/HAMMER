#!/bin/bash
# run_e6.sh — E6: Scalability (3-party, all queries, SF sweep)
# Runs Q1,Q4,Q5,Q6,Q12,Q19 at SF=0.01,0.1,1 in real 3-party setting.
# Party B: g5.16xlarge (64P/128H) — matches HADES max thread count.
# 1 run per (query, SF).
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

parse_common_args "$@"
SF_LIST="${SF_LIST:-0.01 0.1 1}"
REPS=1
TIMEOUT=3600
common_init

QUERIES=(q1 q4 q5 q6 q12 q19)
OUT_DIR="./data/paper_runs/E6/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

echo "════════════════════════════════════════════════════════════"
echo "  E6: Scalability (3-party)"
echo "  Queries:   ${QUERIES[*]}"
echo "  SF sweep:  ${SF_LIST}"
echo "  Reps:      ${REPS}"
echo "  Threads:   H=${H}"
echo "  Timeout:   ${TIMEOUT}s per run"
echo "  Output:    ${OUT_DIR}"
echo "════════════════════════════════════════════════════════════"

# ── Results CSV ──────────────────────────────────────────────────
RESULTS_CSV="${OUT_DIR}/e6_results.csv"
echo "query,sf,run,filter_ms,agg_ms,total_sec,status" > "$RESULTS_CSV"

for SF in $SF_LIST; do
  for Q in "${QUERIES[@]}"; do
    GF="${QUERY_FILTER[$Q]}"

    for RUN in $(seq 1 $REPS); do
      PREFIX="${OUT_DIR}/e6_${Q}_$(sf_label $SF)_run${RUN}"

      if already_passed "$PREFIX"; then
          echo "[E6] ${Q} $(sf_label $SF) run${RUN} — SKIP (already passed)"
      else
          echo "[E6] ${Q} $(sf_label $SF) run${RUN} (3-party, OMP=${H})"
          run_3party "$SF" "$GF" "$H" "$PREFIX"
      fi

      # Extract timing from Party B log
      local_log="${PREFIX}_party_b.log"
      status="FAILED"
      filter_ms="0" agg_ms="0" total_sec="0"
      if [ -f "$local_log" ]; then
          if grep -q '\[  PASSED  \] [1-9]' "$local_log" 2>/dev/null; then
              status="PASSED"
          fi
          read -r filter_ms agg_ms total_sec <<< "$(extract_timing "$local_log")"
      fi
      echo "${Q},${SF},${RUN},${filter_ms},${agg_ms},${total_sec},${status}" >> "$RESULTS_CSV"
    done
  done
  echo ""
done

echo "  Raw results: ${RESULTS_CSV}"

# ── Summary CSV ───────────────────────────────────────────────────
SUMMARY_CSV="${OUT_DIR}/e6_summary.csv"
echo "query,sf,filter_ms,agg_ms,total_sec" > "$SUMMARY_CSV"

for SF in $SF_LIST; do
  for Q in "${QUERIES[@]}"; do
    f=$(grep "^${Q},${SF},.*PASSED" "$RESULTS_CSV" | cut -d, -f4 | head -1 || echo "0")
    a=$(grep "^${Q},${SF},.*PASSED" "$RESULTS_CSV" | cut -d, -f5 | head -1 || echo "0")
    t=$(grep "^${Q},${SF},.*PASSED" "$RESULTS_CSV" | cut -d, -f6 | head -1 || echo "0")
    echo "${Q},${SF},${f:-0},${a:-0},${t:-0}" >> "$SUMMARY_CSV"
  done
done

echo "  Summary:     ${SUMMARY_CSV}"
echo ""
cat "$SUMMARY_CSV" | column -t -s,
echo ""
echo "  E6 done."
