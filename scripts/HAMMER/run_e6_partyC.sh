#!/bin/bash
# run_e6_partyC.sh — E6 FHE Param Comparison: Party C (3-server cross-network)
# Start this AFTER Party B, BEFORE Party A.
#
# 3 configs × 3 SFs × 6 queries = 54 runs
#   old   — baseline (N=65536, depth=15) + OMP=P
#   new_P — optimized params + OMP=P
#   new_H — optimized params + OMP=H
#
# Usage: bash scripts/HAMMER/run_e6_partyC.sh --alice_host=<A_IP>
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

ALICE_HOST=""
for arg in "$@"; do
    case "$arg" in
        --alice_host=*) ALICE_HOST="${arg#*=}" ;;
    esac
done
parse_common_args "$@"
SF_LIST="${SF_LIST:-0.01 0.1 1}"
common_init

if [ -z "$ALICE_HOST" ]; then
    echo "[ERROR] --alice_host=<ip> is required (IP for Party A)"
    exit 1
fi

QUERIES=(q1 q4 q5 q6 q12 q19)
CONFIGS="old new_P new_H"
OUT_DIR="./data/paper_runs/E6/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

echo "════════════════════════════════════════════════════════════"
echo "  E6: FHE Param Comparison — Party C on $(hostname)"
echo "  Party A on: ${ALICE_HOST}"
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

      echo "[E6-C] ${CFG} ${Q} $(sf_label $SF) OMP=${threads} — waiting for B and A..."

      pkill -9 -f fhe_tpch_test 2>/dev/null || true
      sleep 2

      # Party C (listens on PORT_C for A, listens on MPC_PORT for B)
      stdbuf -o0 -e0 env OMP_NUM_THREADS="$threads" \
          "$FHE_BINARY" \
          --fhe_party=3 --party=3 \
          --fhe_charlie_port="$PORT_C" \
          --fhe_mpc_port="$MPC_PORT" \
          --alice_host="$ALICE_HOST" \
          --unioned_db="tpch_unioned_$(sf_to_db $SF)" \
          --filter="${GF}" \
          --validation=true \
          --server_profile="$PROFILE_JSON" \
          $extra \
          > "${PREFIX}_party_c.log" 2>&1

      if grep -q '\[  PASSED  \] [1-9]' "${PREFIX}_party_c.log" 2>/dev/null; then
          echo "    PASSED"
      else
          echo "    FAILED — check ${PREFIX}_party_c.log"
      fi
    done
  done
  echo ""
done

echo "  E6 Party C done."
