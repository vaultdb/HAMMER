#!/bin/bash
# run_e4.sh — E4: Comparator Base Ablation (all 6 queries)
# Varies radixBase for each query's filter: base 2, 4, 8, 16.
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

parse_common_args "$@"
SF_LIST="${SF_LIST:-0.01}"
common_init
ensure_data_loaded "$SF_LIST"

OUT_DIR="./data/paper_runs/E4/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

BASES=(2 4 8 16)
QUERIES=(q1 q4 q5 q6 q12 q19)
CWD="$(pwd)"

echo "════════════════════════════════════════════════════════════"
echo "  E4: Comparator Base Ablation"
echo "  Queries: ${QUERIES[*]}"
echo "  Bases: ${BASES[*]}, SF: ${SF_LIST}"
echo "════════════════════════════════════════════════════════════"

for SF in $SF_LIST; do
  for Q in "${QUERIES[@]}"; do
    GF="${QUERY_FILTER[$Q]}"
    for BASE in "${BASES[@]}"; do
      PLAN_PATH="${CWD}/conf/plans/fhe/base_ablation/${Q}_base${BASE}.json"

      if [[ ! -f "$PLAN_PATH" ]]; then
          echo "[E4] ${Q} $(sf_label $SF) base=${BASE} — SKIP (no plan file)"
          continue
      fi

      PREFIX="${OUT_DIR}/e4_base${BASE}_${Q}_$(sf_label $SF)"
      if already_passed "$PREFIX"; then
          echo "[E4] ${Q} $(sf_label $SF) base=${BASE} — SKIP (already passed)"
      else
          echo "[E4] ${Q} $(sf_label $SF) base=${BASE} T=${P}"
          run_3party "$SF" "$GF" "$P" "$PREFIX" "--fhe_plan_path_override=${PLAN_PATH} --fhe_force_threads=${P}"
      fi
    done
    echo ""
  done
done

parse_results "$OUT_DIR"
echo "  E4 done."
