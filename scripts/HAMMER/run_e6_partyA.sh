#!/bin/bash
# run_e6_partyA.sh — E6 FHE Param Comparison: Party A (3-server cross-network)
# Start this LAST, after Party B and Party C are both running.
#
# 3 configs × 3 SFs × 6 queries = 54 runs
#   old   — baseline (N=65536, depth=15) + OMP=P
#   new_P — optimized params + OMP=P
#   new_H — optimized params + OMP=H
#
# Usage: bash scripts/HAMMER/run_e6_partyA.sh --bob_host=<B_IP> --charlie_host=<C_IP>
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

BOB_HOST=""
CHARLIE_HOST=""
for arg in "$@"; do
    case "$arg" in
        --bob_host=*)     BOB_HOST="${arg#*=}" ;;
        --charlie_host=*) CHARLIE_HOST="${arg#*=}" ;;
    esac
done
parse_common_args "$@"
SF_LIST="${SF_LIST:-0.01 0.1 1}"
common_init

if [ -z "$BOB_HOST" ]; then
    echo "[ERROR] --bob_host=<ip> is required (IP for Party B)"
    exit 1
fi
if [ -z "$CHARLIE_HOST" ]; then
    echo "[ERROR] --charlie_host=<ip> is required (IP for Party C)"
    exit 1
fi

QUERIES=(q1 q4 q5 q6 q12 q19)
CONFIGS="old new_P new_H"
OUT_DIR="./data/paper_runs/E6/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

echo "════════════════════════════════════════════════════════════"
echo "  E6: FHE Param Comparison — Party A on $(hostname)"
echo "  Party B on: ${BOB_HOST}"
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

      echo "[E6-A] ${CFG} ${Q} $(sf_label $SF) OMP=${threads} — connecting to B and C..."

      pkill -9 -f fhe_tpch_test 2>/dev/null || true
      sleep 2

      # Party A (connects to B on BOB_HOST:PORT_B, connects to C on CHARLIE_HOST:PORT_C)
      stdbuf -o0 -e0 env OMP_NUM_THREADS="$threads" \
          "$FHE_BINARY" \
          --fhe_party=1 --party=1 \
          --fhe_port="$PORT_B" \
          --fhe_charlie_port="$PORT_C" \
          --fhe_mpc_port="$MPC_PORT" \
          --fhe_bob_host="$BOB_HOST" \
          --fhe_charlie_host="$CHARLIE_HOST" \
          --unioned_db="tpch_unioned_$(sf_to_db $SF)" \
          --filter="${GF}" \
          --validation=true \
          --server_profile="$PROFILE_JSON" \
          $extra \
          > "${PREFIX}_party_a.log" 2>&1

      if grep -q '\[  PASSED  \] [1-9]' "${PREFIX}_party_a.log" 2>/dev/null; then
          echo "    PASSED"
      else
          echo "    FAILED — check ${PREFIX}_party_a.log"
      fi
    done
  done
  echo ""
done

echo "  E6 Party A done."
