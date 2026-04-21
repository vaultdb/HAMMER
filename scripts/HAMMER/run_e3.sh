#!/bin/bash
# run_e3.sh — E3: SCS + MPC Sort vs Engorgio HomSort
# Uses sort_lineitem test (FheTableScan → SCS → LogicalSort) to isolate sort cost.
# Sweeps --sort_limit to control output cardinality.
# Fixed SF=0.01 (tpch_unioned_1500).
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

parse_common_args "$@"
SF_LIST="${SF_LIST:-0.01}"
common_init

OUT_DIR="./data/paper_runs/E3/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

SORT_LIMITS=(64 256 1024 4096 8192)
GF="${QUERY_FILTER[sort_lineitem]}"

echo "════════════════════════════════════════════════════════════"
echo "  E3: SCS + MPC Sort vs Engorgio HomSort"
echo "  Test: sort_lineitem (FheTableScan → SCS → Sort)"
echo "  Sort limits: ${SORT_LIMITS[*]}, SF: ${SF_LIST}"
echo "════════════════════════════════════════════════════════════"

for SF in $SF_LIST; do
  for LIMIT in "${SORT_LIMITS[@]}"; do
    PREFIX="${OUT_DIR}/e3_sort_${LIMIT}_$(sf_label $SF)"
    if already_passed "$PREFIX"; then
        echo "[E3] sort_limit=${LIMIT} $(sf_label $SF) — SKIP (already passed)"
    else
        echo "[E3] sort_limit=${LIMIT} $(sf_label $SF) T=${P}"
        run_3party "$SF" "$GF" "$P" "$PREFIX" "--sort_limit=${LIMIT} --fhe_force_threads=${P}"
    fi
  done
  echo ""
done

# ── Extract SCS and Sort times from party_b logs ──────────────
echo ""
echo "=== E3 Timing Breakdown ==="
printf "%-12s %12s %12s %12s\n" "sort_limit" "scs_ms" "sort_ms" "total_ms"
echo "----------------------------------------------------"
for LIMIT in "${SORT_LIMITS[@]}"; do
    LOG="${OUT_DIR}/e3_sort_${LIMIT}_$(sf_label $SF)_party_b.log"
    if [ ! -f "$LOG" ]; then
        printf "%-12s %12s %12s %12s\n" "$LIMIT" "N/A" "N/A" "N/A"
        continue
    fi
    scs_ms=$(grep -oP 'SecureContextSwitch ran for \K[0-9.]+' "$LOG" 2>/dev/null | head -1 || true)
    sort_ms=$(grep -oP 'Sort ran for \K[0-9.]+' "$LOG" 2>/dev/null | head -1 || true)
    scs_ms="${scs_ms:-N/A}"
    sort_ms="${sort_ms:-N/A}"
    if [[ "$scs_ms" != "N/A" && "$sort_ms" != "N/A" ]]; then
        total_ms=$(python3 -c "print(f'{${scs_ms} + ${sort_ms}:.3f}')" 2>/dev/null || echo "N/A")
    else
        total_ms="N/A"
    fi
    printf "%-12s %12s %12s %12s\n" "$LIMIT" "$scs_ms" "$sort_ms" "$total_ms"
done

parse_results "$OUT_DIR"
echo "  E3 done."
