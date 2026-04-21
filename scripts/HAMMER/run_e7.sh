#!/bin/bash
# run_e7.sh — E7: Scalability (all queries, CPU + GPU)
# CPU: 3-party FHE full pipeline (filter + agg + SCS + MPC sort) at SF 0.1, 1
# GPU: single-process (filter + aggregate only) at SF 0.1, 1, 10
# Per-phase timing extracted from Party B logs.
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

parse_common_args "$@"
CPU_SF="${CPU_SF:-0.1 1}"
GPU_SF="${GPU_SF:-0.1 1 10}"
REPS=1
common_init

# ── Ensure TPC-H data is loaded for all requested SFs ────────────
ensure_data_loaded "$CPU_SF $GPU_SF"

QUERIES=(q1 q4 q5 q6 q12 q19)
OUT_DIR="./data/paper_runs/E7/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

echo "════════════════════════════════════════════════════════════"
echo "  E7: Scalability"
echo "  Queries:   ${QUERIES[*]}"
echo "  CPU SF:    ${CPU_SF}"
echo "  GPU SF:    ${GPU_SF}"
echo "  Reps:      ${REPS}"
echo "  Threads:   H=${H}"
echo "  Output:    ${OUT_DIR}"
echo "════════════════════════════════════════════════════════════"

# ── Results CSV ──────────────────────────────────────────────────
RESULTS_CSV="${OUT_DIR}/e7_results.csv"
echo "mode,query,sf,run,filter_ms,agg_ms,total_sec,status" > "$RESULTS_CSV"

# ── CPU runs (3-party, full pipeline) ────────────────────────────
echo ""
echo "=== CPU runs (3-party, OMP=${H}) ==="
for SF in $CPU_SF; do
  for Q in "${QUERIES[@]}"; do
    GF="${QUERY_FILTER[$Q]}"

    for RUN in $(seq 1 $REPS); do
      PREFIX="${OUT_DIR}/e7_cpu_${Q}_$(sf_label $SF)_run${RUN}"

      if already_passed "$PREFIX"; then
          echo "[E7] CPU ${Q} $(sf_label $SF) run${RUN} — SKIP (already passed)"
      else
          echo "[E7] CPU ${Q} $(sf_label $SF) run${RUN}"
          run_3party "$SF" "$GF" "$H" "$PREFIX"
      fi

      local_log="${PREFIX}_party_b.log"
      status="FAILED"; filter_ms="0"; agg_ms="0"; total_sec="0"
      if [ -f "$local_log" ]; then
          if grep -q '\[  PASSED  \] [1-9]' "$local_log" 2>/dev/null; then
              status="PASSED"
          fi
          read -r filter_ms agg_ms total_sec <<< "$(extract_timing "$local_log")"
      fi
      echo "cpu,${Q},${SF},${RUN},${filter_ms},${agg_ms},${total_sec},${status}" >> "$RESULTS_CSV"
    done
  done
  echo ""
done

# ── GPU runs (single-process, filter + aggregate only) ───────────
echo ""
echo "=== GPU runs (single-process) ==="
for SF in $GPU_SF; do
  for Q in "${QUERIES[@]}"; do
    GF="${GPU_QUERY_FILTER[$Q]}"

    for RUN in $(seq 1 $REPS); do
      PREFIX="${OUT_DIR}/e7_gpu_${Q}_$(sf_label $SF)_run${RUN}"

      if already_passed "$PREFIX"; then
          echo "[E7] GPU ${Q} $(sf_label $SF) run${RUN} — SKIP (already passed)"
      else
          echo "[E7] GPU ${Q} $(sf_label $SF) run${RUN}"
          run_gpu_single "$SF" "$GF" "$PREFIX"
      fi

      local_log="${PREFIX}_party_b.log"
      status="FAILED"; filter_ms="0"; agg_ms="0"; total_sec="0"
      if [ -f "$local_log" ]; then
          if grep -q '\[  PASSED  \] [1-9]' "$local_log" 2>/dev/null; then
              status="PASSED"
          fi
          read -r filter_ms agg_ms total_sec <<< "$(extract_timing "$local_log")"
      fi
      echo "gpu,${Q},${SF},${RUN},${filter_ms},${agg_ms},${total_sec},${status}" >> "$RESULTS_CSV"
    done
  done
  echo ""
done

echo "  Results: ${RESULTS_CSV}"
echo ""
cat "$RESULTS_CSV" | column -t -s,
echo ""
echo "  E7 done."
