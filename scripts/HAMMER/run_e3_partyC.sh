#!/bin/bash
# run_e3_partyC.sh — E3 Party C (run on codd07)
# Start this BEFORE run_e3_partyBA.sh on IIT
#
# Usage: bash scripts/HAMMER/run_e3_partyC.sh --alice_host=216.47.152.56
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
SF_LIST="${SF_LIST:-0.01}"
common_init

if [ -z "$ALICE_HOST" ]; then
    echo "[ERROR] --alice_host=<iit_ip> is required (IP of machine running Party A+B)"
    exit 1
fi
echo "  Party A+B host: ${ALICE_HOST}"

OUT_DIR="./data/paper_runs/E3/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

SORT_LIMITS=(64 256 1024 4096 8192)
GF="${QUERY_FILTER[sort_lineitem]}"

echo "════════════════════════════════════════════════════════════"
echo "  E3: SCS + MPC Sort (Party C on $(hostname))"
echo "  Party A+B on: ${ALICE_HOST}"
echo "  Listening for connections..."
echo "  Sort limits: ${SORT_LIMITS[*]}, SF: ${SF_LIST}"
echo "════════════════════════════════════════════════════════════"

for SF in $SF_LIST; do
  for LIMIT in "${SORT_LIMITS[@]}"; do
    PREFIX="${OUT_DIR}/e3_sort_${LIMIT}_$(sf_label $SF)"

    echo "[E3-C] sort_limit=${LIMIT} $(sf_label $SF) — waiting for B+A..."

    # Kill any leftover local processes
    pkill -9 -f fhe_tpch_test 2>/dev/null || true
    sleep 2

    EXTRA="--sort_limit=${LIMIT} --fhe_force_threads=${P}"

    # Party C (listens on 8766 for A, connects to A+B for MPC)
    stdbuf -o0 -e0 env OMP_NUM_THREADS="$P" \
        "$FHE_BINARY" \
        --fhe_party=3 --party=3 \
        --fhe_charlie_port="$PORT_C" \
        --fhe_mpc_port="$MPC_PORT" \
        --alice_host="$ALICE_HOST" \
        --unioned_db="tpch_unioned_$(sf_to_db $SF)" \
        --filter="${GF}" \
        --validation=true \
        --server_profile="$PROFILE_JSON" \
        $EXTRA \
        > "${PREFIX}_party_c.log" 2>&1

    if grep -q '\[  PASSED  \] [1-9]' "${PREFIX}_party_c.log" 2>/dev/null; then
        echo "    PASSED"
    else
        echo "    FAILED — check ${PREFIX}_party_c.log"
    fi
  done
  echo ""
done

echo "  E3 Party C done."
