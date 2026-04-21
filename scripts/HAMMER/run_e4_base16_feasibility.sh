#!/bin/bash
# run_e4_base16_feasibility.sh — E4 Task 1: Base-16 feasibility check
#
# Runs Q1 with base=16 at ring_dim=65536, mult_depth=21 (safe buffer above
# actual Phase A linear chain depth ~18).
#
# Goal: Determine if OpenFHE accepts (65536, 21) or rejects with security error.
#   - If accepted: run to completion, record Total(ms)
#   - If rejected: record error message and log2Q value
#
# Usage: bash scripts/HAMMER/run_e4_base16_feasibility.sh [--sf=0.01]
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
PLAN_PATH="${CWD}/conf/plans/fhe/base_ablation/q1_base16.json"

RING_DIM=65536
MULT_DEPTH=21

echo "════════════════════════════════════════════════════════════"
echo "  E4 Task 1: Base-16 Feasibility Check"
echo "  ring_dim=${RING_DIM}, mult_depth=${MULT_DEPTH}"
echo "  Plan: ${PLAN_PATH}"
echo "  SF: ${SF_LIST}"
echo "════════════════════════════════════════════════════════════"

for SF in $SF_LIST; do
    PREFIX="${OUT_DIR}/e4_base16_feasibility_$(sf_label $SF)"

    echo "[E4-feasibility] base=16 ring_dim=${RING_DIM} mult_depth=${MULT_DEPTH} $(sf_label $SF)"

    run_3party "$SF" "$GF" "$P" "$PREFIX" \
        "--fhe_plan_path_override=${PLAN_PATH} --fhe_force_ring_dim=${RING_DIM} --fhe_force_mult_depth=${MULT_DEPTH} --fhe_force_threads=${P}"

    # Check for OpenFHE security rejection
    for role in a b c; do
        LOG="${PREFIX}_party_${role}.log"
        if [ -f "$LOG" ]; then
            if grep -qi 'security\|not supported\|too large\|abort\|log2 q' "$LOG" 2>/dev/null; then
                echo "    [Party ${role}] Possible security rejection:"
                grep -i 'security\|not supported\|too large\|abort\|log2 q\|log2Q\|FAILED' "$LOG" | head -5
            fi
        fi
    done

    # Extract timing if it passed
    LOG_B="${PREFIX}_party_b.log"
    if [ -f "$LOG_B" ] && grep -q '\[  PASSED  \] [1-9]' "$LOG_B" 2>/dev/null; then
        TOTAL_MS=$(grep -oP 'Total[^:]*:\s*\K[0-9.]+' "$LOG_B" 2>/dev/null | head -1 || true)
        echo "    Total(ms): ${TOTAL_MS:-N/A}"
    fi

    echo ""
done

echo "════════════════════════════════════════════════════════════"
echo "  E4 Task 1 done. Check logs in ${OUT_DIR}/"
echo "════════════════════════════════════════════════════════════"
