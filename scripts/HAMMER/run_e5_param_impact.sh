#!/bin/bash
# run_e5_param_impact.sh — E5: FHE Parameter Impact (ring_dim + multDepth)
# Compares optimized per-query params vs fixed (65536, 21) baseline.
# Both configs use T = P (physical cores only, no hyperthreading).
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

parse_common_args "$@"
SF_LIST="${SF_LIST:-0.01 0.1 1}"
common_init

# ── Ensure TPC-H data is loaded for all requested SFs ────────────
ensure_data_loaded "$SF_LIST"

OUT_DIR="./data/paper_runs/E5_param/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

QUERIES=(q1 q4 q5 q6 q12 q19)

# Baseline params: ring_dim=65536, multDepth=21
BASELINE_RING=65536
BASELINE_DEPTH=21

echo "════════════════════════════════════════════════════════════"
echo "  E5: FHE Parameter Impact"
echo "  Queries:  ${QUERIES[*]}"
echo "  SF:       ${SF_LIST}"
echo "  Threads:  T = P = ${P} (physical cores)"
echo "  Config A: optimized (per-query ring_dim + multDepth)"
echo "  Config B: baseline  (N=${BASELINE_RING}, d=${BASELINE_DEPTH})"
echo "════════════════════════════════════════════════════════════"

for SF in $SF_LIST; do
  for Q in "${QUERIES[@]}"; do
    GF="${QUERY_FILTER[$Q]}"

    # ── Config A: Optimized (auto ring_dim + multDepth), T=P ──
    PREFIX="${OUT_DIR}/e5_opt_${Q}_$(sf_label $SF)"
    if already_passed "$PREFIX"; then
        echo "[E5-opt] ${Q} $(sf_label $SF) T=${P} — SKIP"
    else
        echo "[E5-opt] ${Q} $(sf_label $SF) T=${P}"
        run_3party "$SF" "$GF" "$P" "$PREFIX" "--fhe_force_threads=${P}"
    fi

    # ── Config B: Baseline (N=65536, d=21), T=P ──
    PREFIX="${OUT_DIR}/e5_base_${Q}_$(sf_label $SF)"
    if already_passed "$PREFIX"; then
        echo "[E5-base] ${Q} $(sf_label $SF) T=${P} — SKIP"
    else
        echo "[E5-base] ${Q} $(sf_label $SF) T=${P}"
        run_3party "$SF" "$GF" "$P" "$PREFIX" \
            "--fhe_force_ring_dim=${BASELINE_RING} --fhe_force_mult_depth=${BASELINE_DEPTH} --fhe_force_threads=${P}"
    fi

    echo ""
  done
done

parse_results "$OUT_DIR"
echo "  E5 param impact done."
