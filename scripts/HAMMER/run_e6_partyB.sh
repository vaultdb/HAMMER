#!/bin/bash
# run_e6_partyB.sh — E6 FHE Param Comparison: Party B (3-server cross-network)
# Start this FIRST, then Party C, then Party A.
#
# 3 configs × 3 SFs × 6 queries = 54 runs
#   old   — baseline (N=65536, depth=15) + OMP=P
#   new_P — optimized params + OMP=P
#   new_H — optimized params + OMP=H
#
# Usage: bash scripts/HAMMER/run_e6_partyB.sh --charlie_host=<C_IP>
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

CHARLIE_HOST=""
for arg in "$@"; do
    case "$arg" in
        --charlie_host=*) CHARLIE_HOST="${arg#*=}" ;;
    esac
done
parse_common_args "$@"
SF_LIST="${SF_LIST:-0.01 0.1 1}"
common_init

if [ -z "$CHARLIE_HOST" ]; then
    echo "[ERROR] --charlie_host=<ip> is required (IP for Party C)"
    exit 1
fi

QUERIES=(q1 q4 q5 q6 q12 q19)
CONFIGS="old new_P new_H"
OUT_DIR="./data/paper_runs/E6/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

# ── Results CSV ──────────────────────────────────────────────────
RESULTS_CSV="${OUT_DIR}/e6_results.csv"
if [ ! -f "$RESULTS_CSV" ]; then
    echo "query,sf,config,filter_ms,agg_ms,total_sec,status" > "$RESULTS_CSV"
fi

echo "════════════════════════════════════════════════════════════"
echo "  E6: FHE Param Comparison — Party B on $(hostname)"
echo "  Party C on: ${CHARLIE_HOST}"
echo "  Queries:    ${QUERIES[*]}"
echo "  Configs:    ${CONFIGS}"
echo "  SF sweep:   ${SF_LIST}"
echo "  Threads:    P=${P}  H=${H}"
echo "════════════════════════════════════════════════════════════"

for SF in $SF_LIST; do
  for Q in "${QUERIES[@]}"; do
    GF="${QUERY_FILTER[$Q]}"

    for CFG in $CONFIGS; do
      case "$CFG" in
        old)    threads=$P; extra="--fhe_force_baseline --fhe_force_threads=$P" ;;
        new_P)  threads=$P; extra="--fhe_force_threads=$P" ;;
        new_H)  threads=$H; extra="" ;;
      esac

      PREFIX="${OUT_DIR}/e6_${CFG}_${Q}_$(sf_label $SF)"

      echo "[E6-B] ${CFG} ${Q} $(sf_label $SF) OMP=${threads} — waiting for C and A..."

      pkill -9 -f fhe_tpch_test 2>/dev/null || true
      sleep 2

      # Party B (listens on PORT_B for A, connects to C for SCS/MPC)
      stdbuf -o0 -e0 env OMP_NUM_THREADS="$threads" \
          "$FHE_BINARY" \
          --fhe_party=2 --party=2 \
          --fhe_port="$PORT_B" \
          --fhe_mpc_port="$MPC_PORT" \
          --fhe_charlie_host="$CHARLIE_HOST" \
          --unioned_db="tpch_unioned_$(sf_to_db $SF)" \
          --filter="${GF}" \
          --validation=true \
          --server_profile="$PROFILE_JSON" \
          $extra \
          > "${PREFIX}_party_b.log" 2>&1

      if grep -q '\[  PASSED  \] [1-9]' "${PREFIX}_party_b.log" 2>/dev/null; then
          echo "    PASSED"
      else
          echo "    FAILED — check ${PREFIX}_party_b.log"
      fi

      # Extract timing from Party B log into CSV
      local_log="${PREFIX}_party_b.log"
      status="FAILED"; filter_ms="0"; agg_ms="0"; total_sec="0"
      if [ -f "$local_log" ]; then
          if grep -q '\[  PASSED  \] [1-9]' "$local_log" 2>/dev/null; then
              status="PASSED"
          fi
          read -r filter_ms agg_ms total_sec <<< "$(extract_timing "$local_log")"
      fi
      echo "${Q},${SF},${CFG},${filter_ms},${agg_ms},${total_sec},${status}" >> "$RESULTS_CSV"
    done
  done
  echo ""
done

echo "  Results: ${RESULTS_CSV}"
echo ""
cat "$RESULTS_CSV" | column -t -s,
echo ""
echo "  E6 Party B done."
