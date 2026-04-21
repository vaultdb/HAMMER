#!/bin/bash
# run_e7_partyC.sh — E7 Scalability: Party C (run on codd07)
# Start this BEFORE run_e7_partyBA.sh on IIT
#
# Usage: bash scripts/HAMMER/run_e7_partyC.sh --alice_host=216.47.152.56
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
SF_LIST="${SF_LIST:-0.1 1 10}"
REPS=1
common_init

if [ -z "$ALICE_HOST" ]; then
    echo "[ERROR] --alice_host=<iit_ip> is required (IP of machine running Party B+A)"
    exit 1
fi
echo "  Party B+A host: ${ALICE_HOST}"

QUERIES=(q1 q4 q5 q6 q12 q19)
OUT_DIR="./data/paper_runs/E7/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

echo "════════════════════════════════════════════════════════════"
echo "  E7: Scalability — Party C on $(hostname)"
echo "  Party B+A on: ${ALICE_HOST}"
echo "  Queries:      ${QUERIES[*]}"
echo "  SF sweep:     ${SF_LIST}"
echo "════════════════════════════════════════════════════════════"

for SF in $SF_LIST; do
  for Q in "${QUERIES[@]}"; do
    GF="${QUERY_FILTER[$Q]}"

    for RUN in $(seq 1 $REPS); do
      PREFIX="${OUT_DIR}/e7_cpu_${Q}_$(sf_label $SF)_run${RUN}"

      echo "[E7-C] ${Q} $(sf_label $SF) run${RUN} — waiting for B+A..."

      pkill -9 -f fhe_tpch_test 2>/dev/null || true
      sleep 2

      # Party C (listens on PORT_C for A, listens on MPC_PORT for B)
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

echo "  E7 Party C done."
