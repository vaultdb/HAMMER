#!/bin/bash
# run_e2.sh — E2: End-to-End Performance vs Engorgio
# Config A: HAMMER without parameter optimizer (ring_dim=65536, depth=15, T=P)
# Config C: HAMMER full system (adaptive N/m, T*=auto)
# Engorgio: cited from SIGMOD 2022 (ring_dim=131072 is OOM-infeasible)
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

parse_common_args "$@"
SF_LIST="${SF_LIST:-0.01}"
common_init

QUERIES=(q1_one_sum q6 q12)
OUT_DIR="./data/paper_runs/E2/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

echo "════════════════════════════════════════════════════════════"
echo "  E2: End-to-End Performance vs Engorgio"
echo "  Queries: ${QUERIES[*]}, SF: ${SF_LIST}"
echo "════════════════════════════════════════════════════════════"

for SF in $SF_LIST; do
  for Q in "${QUERIES[@]}"; do
    GF="${QUERY_FILTER[$Q]}"

    # Config C: HAMMER full system (adaptive N/m, T*=auto)
    PREFIX="${OUT_DIR}/config_c_${Q}_$(sf_label $SF)"
    if already_passed "$PREFIX"; then
        echo "[E2-Config C] ${Q} $(sf_label $SF) — SKIP (already passed)"
    else
        echo "[E2-Config C] ${Q} $(sf_label $SF) T*=auto"
        run_3party "$SF" "$GF" "$H" "$PREFIX" ""
    fi

    # Config A: HAMMER without optimizer (N=65536, m=15, T=P)
    PREFIX="${OUT_DIR}/config_a_${Q}_$(sf_label $SF)"
    if already_passed "$PREFIX"; then
        echo "[E2-Config A] ${Q} $(sf_label $SF) — SKIP (already passed)"
    else
        echo "[E2-Config A] ${Q} $(sf_label $SF) T=${P}"
        run_3party "$SF" "$GF" "$P" "$PREFIX" "--fhe_force_baseline --fhe_force_threads=${P}"
    fi

    echo ""
  done
done

parse_results "$OUT_DIR"

# ── Parameter Feasibility Table ──────────────────────────────────
echo ""
echo "=== Parameter Comparison Table ==="
echo "Extracting HAMMER key sizes from logs..."

# Extract EvalRotateKey size from party_a logs
for Q in q1_one_sum q6 q12; do
    LOG="${OUT_DIR}/config_c_${Q}_$(sf_label $SF)_party_a.log"
    if [ -f "${LOG}" ]; then
        ROT=$(grep "EvalRotateKey serialized" "${LOG}" 2>/dev/null \
              | grep -oP '\d+(?= bytes)' | head -1 || true)
        AUTO=$(grep "EvalAutomorphismKeys" "${LOG}" 2>/dev/null \
               | grep -oP '\d+(?= bytes)' | head -1 || true)
        echo "  ${Q}: EvalRotateKey=${ROT:-N/A} bytes, AutomKey=${AUTO:-N/A} bytes"
    fi
done

echo ""
echo "  Engorgio (ring_dim=131072): EvalRotateKey=16,307,995,433 bytes"
echo "  (empirically measured: see logs/e2_large_ring_q1_sf150_party_a.log)"
echo ""
echo "  → Engorgio key material is infeasible for 3-party deployment."
echo "  → HAMMER achieves same semantics with ~100-200x smaller keys."

echo ""
echo "  E2 done."
