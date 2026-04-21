#!/bin/bash
# run_e5.sh — E5: SMT Policy Portability
# Thread sweep for Q1 and Q5, comparing old (baseline) vs new (adaptive) paths.
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

parse_common_args "$@"
SF_LIST="${SF_LIST:-0.1}"
common_init

OUT_DIR="./data/paper_runs/E5/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

QUERIES=(q1 q5 q12)

# Compute thread sweep values: {P/2, P, 3P/2, 2P, H} deduplicated
HALF_P=$(( P / 2 ))
(( HALF_P < 1 )) && HALF_P=1
MID_P=$(( P * 3 / 2 ))
TWO_P=$(( P * 2 ))
SWEEP_THREADS=$(echo "${HALF_P} ${P} ${MID_P} ${TWO_P} ${H}" | tr ' ' '\n' | sort -n -u | tr '\n' ' ')

echo "════════════════════════════════════════════════════════════"
echo "  E5: SMT Policy Portability"
echo "  Queries: ${QUERIES[*]}, Threads: ${SWEEP_THREADS}"
echo "  SF: ${SF_LIST}"
echo "════════════════════════════════════════════════════════════"

for SF in $SF_LIST; do
  for Q in "${QUERIES[@]}"; do
    GF="${QUERY_FILTER[$Q]}"

    for T in $SWEEP_THREADS; do
      # Old path: baseline (N=65536, depth=15)
      PREFIX="${OUT_DIR}/e5_old_${Q}_$(sf_label $SF)_T${T}"
      if already_passed "$PREFIX"; then
          echo "[E5-old] ${Q} $(sf_label $SF) T=${T} — SKIP"
      else
          echo "[E5-old] ${Q} $(sf_label $SF) T=${T}"
          run_3party "$SF" "$GF" "$T" "$PREFIX" "--fhe_force_baseline --fhe_force_threads=${T}"
      fi

      # New path: adaptive (N,m auto)
      PREFIX="${OUT_DIR}/e5_new_${Q}_$(sf_label $SF)_T${T}"
      if already_passed "$PREFIX"; then
          echo "[E5-new] ${Q} $(sf_label $SF) T=${T} — SKIP"
      else
          echo "[E5-new] ${Q} $(sf_label $SF) T=${T}"
          run_3party "$SF" "$GF" "$T" "$PREFIX" "--fhe_force_threads=${T}"
      fi
    done

    # Auto config (T*=auto, no force)
    PREFIX="${OUT_DIR}/e5_auto_${Q}_$(sf_label $SF)"
    if already_passed "$PREFIX"; then
        echo "[E5-auto] ${Q} $(sf_label $SF) T*=auto — SKIP"
    else
        echo "[E5-auto] ${Q} $(sf_label $SF) T*=auto"
        run_3party "$SF" "$GF" "$H" "$PREFIX" ""
    fi

    echo ""
  done
done

parse_results "$OUT_DIR"
echo "  E5 done."
