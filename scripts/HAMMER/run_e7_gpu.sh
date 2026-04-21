#!/bin/bash
# run_e7_gpu.sh — E7 GPU-only: single-server GPU filter + aggregate
# Runs all 6 TPC-H queries at specified scale factors.
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

parse_common_args "$@"
GPU_SF="${GPU_SF:-0.01 0.1 1 10}"
REPS="${REPS:-1}"

# GPU-only: skip CPU preflight, just check GPU binary
if [ -z "$SERVER_NAME" ]; then
    SERVER_NAME="$(hostname | cut -d. -f1)"
fi

if [[ ! -x "$GPU_BINARY" ]]; then
    echo "[ERROR] GPU binary not found: $GPU_BINARY"
    echo "  Run 'cmake -DENABLE_GPU=ON . && make -j4 gpu_fhe_tpch_test' first."
    exit 1
fi

# ── Ensure TPC-H data is loaded for all requested SFs ────────────
ensure_data_loaded "$GPU_SF"

QUERIES=(q1 q4 q5 q6 q12 q19)
OUT_DIR="./data/paper_runs/E7/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

echo "════════════════════════════════════════════════════════════"
echo "  E7 GPU-only: Filter + Aggregate (single server)"
echo "  Server:    ${SERVER_NAME}"
echo "  Queries:   ${QUERIES[*]}"
echo "  GPU SF:    ${GPU_SF}"
echo "  Reps:      ${REPS}"
echo "  Binary:    ${GPU_BINARY}"
echo "  Output:    ${OUT_DIR}"
echo "════════════════════════════════════════════════════════════"

# ── Results CSV ──────────────────────────────────────────────────
RESULTS_CSV="${OUT_DIR}/e7_gpu_results.csv"
echo "mode,query,sf,run,filter_ms,agg_ms,total_sec,status" > "$RESULTS_CSV"

# ── GPU runs ─────────────────────────────────────────────────────
for SF in $GPU_SF; do
  for Q in "${QUERIES[@]}"; do
    GF="${GPU_QUERY_FILTER[$Q]}"

    for RUN in $(seq 1 $REPS); do
      PREFIX="${OUT_DIR}/e7_gpu_${Q}_$(sf_label $SF)_run${RUN}"

      if already_passed "$PREFIX"; then
          echo "[E7-GPU] ${Q} $(sf_label $SF) run${RUN} — SKIP (already passed)"
      else
          echo "[E7-GPU] ${Q} $(sf_label $SF) run${RUN}"
          # Tolerate non-zero exit: HEonGPU/RMM crashes during CUDA cleanup
          # even when the test passes.  Rely on log for PASSED/FAILED.
          run_gpu_single "$SF" "$GF" "$PREFIX" || true
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
echo "  E7 GPU-only done."
