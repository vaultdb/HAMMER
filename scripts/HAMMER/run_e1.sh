#!/bin/bash
# run_e1.sh — E1: Selective vs All-Column Encryption
# Measures overhead of encrypting ALL columns (Engorgio-style) vs selective.
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

parse_common_args "$@"
SF_LIST="${SF_LIST:-0.01}"
common_init

QUERIES=(q1_one_sum q6 q12)
OUT_DIR="./data/paper_runs/E1/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

echo "════════════════════════════════════════════════════════════"
echo "  E1: Selective vs All-Column Encryption"
echo "  Queries: ${QUERIES[*]}, SF: ${SF_LIST}"
echo "════════════════════════════════════════════════════════════"

for SF in $SF_LIST; do
  for Q in "${QUERIES[@]}"; do
    GF="${QUERY_FILTER[$Q]}"

    # Selective encryption (default) — baseline params for fair comparison
    PREFIX="${OUT_DIR}/e1_selective_${Q}_$(sf_label $SF)"
    if already_passed "$PREFIX"; then
        echo "[E1-selective] ${Q} $(sf_label $SF) — SKIP (already passed)"
    else
        echo "[E1-selective] ${Q} $(sf_label $SF) T=${P} (baseline N=65536,m=15)"
        run_3party "$SF" "$GF" "$P" "$PREFIX" "--fhe_force_baseline --fhe_force_threads=${P}"
    fi

    # All-column encryption — baseline params for fair comparison
    PREFIX="${OUT_DIR}/e1_allcol_${Q}_$(sf_label $SF)"
    if already_passed "$PREFIX"; then
        echo "[E1-allcol] ${Q} $(sf_label $SF) — SKIP (already passed)"
    else
        echo "[E1-allcol] ${Q} $(sf_label $SF) T=${P} (baseline N=65536,m=15)"
        run_3party "$SF" "$GF" "$P" "$PREFIX" "--fhe_force_baseline --all_column_encrypt --fhe_force_threads=${P}"
    fi

    echo ""
  done
done

parse_results "$OUT_DIR"
echo "  E1 done."
