#!/bin/bash
# run_e4_base64_feasibility.sh — E4 Task 2: Base-64 key/ciphertext size measurement
#
# The linear chain Phase A for base 64 needs ~66 multiplicative levels.
# This script attempts keygen at escalating (ring_dim, mult_depth) to measure:
#   - Whether OpenFHE accepts the params or rejects (security error)
#   - If accepted: log2Q, L (tower count), ct_bytes, working set estimate
#   - EvalMultKey and EvalRotateKey sizes (from memory or log output)
#
# Does NOT expect the full query to complete — just measures param feasibility.
#
# Usage: bash scripts/HAMMER/run_e4_base64_feasibility.sh [--sf=0.01]
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

parse_common_args "$@"
SF_LIST="${SF_LIST:-0.01}"
common_init

OUT_DIR="./data/paper_runs/E4_feasibility/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

GF="${QUERY_FILTER[q1]}"
CWD="$(pwd)"
PLAN_PATH="${CWD}/conf/plans/fhe/base_ablation/q1_base64.json"

# Configs to try: (ring_dim, mult_depth)
# base64 needs ~66 levels. OpenFHE max for 65536 is ~18, for 131072 maybe ~30-35.
# Both will likely fail but we want to see HOW they fail.
declare -a RING_DIMS=(65536 131072)
declare -a MULT_DEPTHS=(66 66)

echo "════════════════════════════════════════════════════════════"
echo "  E4 Task 2: Base-64 Key/CT Size Measurement"
echo "  Plan: ${PLAN_PATH}"
echo "  NOTE: Full query NOT expected to pass."
echo "        Goal is keygen feasibility + size measurements."
echo "════════════════════════════════════════════════════════════"

for SF in $SF_LIST; do
  for i in "${!RING_DIMS[@]}"; do
    RING_DIM="${RING_DIMS[$i]}"
    MULT_DEPTH="${MULT_DEPTHS[$i]}"

    PREFIX="${OUT_DIR}/e4_base64_N${RING_DIM}_m${MULT_DEPTH}_$(sf_label $SF)"

    echo ""
    echo "[E4-base64] ring_dim=${RING_DIM} mult_depth=${MULT_DEPTH} $(sf_label $SF)"
    echo "  Attempting 3-party run (will likely fail at keygen or security check)..."

    run_3party "$SF" "$GF" "$P" "$PREFIX" \
        "--fhe_plan_path_override=${PLAN_PATH} --fhe_force_ring_dim=${RING_DIM} --fhe_force_mult_depth=${MULT_DEPTH} --fhe_force_threads=${P}"

    # Extract diagnostics from whatever logs exist
    for role in a b c; do
        LOG="${PREFIX}_party_${role}.log"
        if [ -f "$LOG" ]; then
            echo "  --- Party ${role} diagnostics ---"
            # log2Q and L from printRnsContextMetrics
            grep -oP 'ring_dim=\d+ batch_size=\d+ L=\d+ log2Q~[0-9.]+' "$LOG" 2>/dev/null | head -3 || true
            # Security errors
            grep -i 'security\|not supported\|too large\|abort\|FATAL\|GenCryptoContext failed' "$LOG" 2>/dev/null | head -3 || true
            # OOM
            grep -i 'bad_alloc\|Cannot allocate\|out of memory\|Killed' "$LOG" 2>/dev/null | head -3 || true
            # Key gen timing
            grep -i 'keys generated\|keygen\|key gen' "$LOG" 2>/dev/null | head -3 || true
        fi
    done
  done
  echo ""
done

echo "════════════════════════════════════════════════════════════"
echo "  E4 Task 2 done. Check logs in ${OUT_DIR}/"
echo ""
echo "  Expected output format:"
echo "  | Base | ring_dim | mult_depth | log2Q | L_eff | ct(MB) | ws(MB) | EvalRotKey(GB) | Status |"
echo "════════════════════════════════════════════════════════════"
