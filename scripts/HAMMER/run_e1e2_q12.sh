#!/bin/bash
# run_e1e2_q12.sh — Quick re-test of E1 + E2 for Q12 only at SF=0.01
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

parse_common_args "$@"
SF_LIST="${SF_LIST:-0.01}"
common_init

Q="q12"
GF="${QUERY_FILTER[$Q]}"

# ── E1: Selective vs All-Column Encryption ──
E1_DIR="./data/paper_runs/E1/${SERVER_NAME}"
mkdir -p "$E1_DIR"

echo "════════════════════════════════════════════════════════════"
echo "  E1 + E2: Q12 only, SF: ${SF_LIST}"
echo "════════════════════════════════════════════════════════════"

for SF in $SF_LIST; do
    PREFIX="${E1_DIR}/e1_selective_${Q}_$(sf_label $SF)"
    if already_passed "$PREFIX"; then
        echo "[E1-selective] ${Q} $(sf_label $SF) — SKIP (already passed)"
    else
        echo "[E1-selective] ${Q} $(sf_label $SF) T=${P} (baseline N=65536,m=15)"
        run_3party "$SF" "$GF" "$P" "$PREFIX" "--fhe_force_baseline --fhe_force_threads=${P}"
    fi

    PREFIX="${E1_DIR}/e1_allcol_${Q}_$(sf_label $SF)"
    if already_passed "$PREFIX"; then
        echo "[E1-allcol] ${Q} $(sf_label $SF) — SKIP (already passed)"
    else
        echo "[E1-allcol] ${Q} $(sf_label $SF) T=${P} (baseline N=65536,m=15)"
        run_3party "$SF" "$GF" "$P" "$PREFIX" "--fhe_force_baseline --all_column_encrypt --fhe_force_threads=${P}"
    fi
done

# ── E2: Config C vs Config A ──
E2_DIR="./data/paper_runs/E2/${SERVER_NAME}"
mkdir -p "$E2_DIR"

for SF in $SF_LIST; do
    PREFIX="${E2_DIR}/config_c_${Q}_$(sf_label $SF)"
    if already_passed "$PREFIX"; then
        echo "[E2-Config C] ${Q} $(sf_label $SF) — SKIP (already passed)"
    else
        echo "[E2-Config C] ${Q} $(sf_label $SF) T*=auto"
        run_3party "$SF" "$GF" "$H" "$PREFIX" ""
    fi

    PREFIX="${E2_DIR}/config_a_${Q}_$(sf_label $SF)"
    if already_passed "$PREFIX"; then
        echo "[E2-Config A] ${Q} $(sf_label $SF) — SKIP (already passed)"
    else
        echo "[E2-Config A] ${Q} $(sf_label $SF) T=${P}"
        run_3party "$SF" "$GF" "$P" "$PREFIX" "--fhe_force_baseline --fhe_force_threads=${P}"
    fi
done

parse_results "$E1_DIR"
parse_results "$E2_DIR"
echo "  E1+E2 Q12 done."
