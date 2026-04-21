#!/bin/bash
# run_e6_mpc_A.sh — E6 MPC Baseline: Party A / Alice (party=1, listener)
# Start this FIRST. Alice listens, then Bob connects.
#
# Usage: bash scripts/HAMMER/run_e6_mpc_A.sh [--sf="0.01 0.1"]
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

MPC_BINARY="${MPC_BINARY:-./bin/mpc_comparison_test}"

parse_common_args "$@"
SF_LIST="${SF_LIST:-0.01 0.1}"
REPS=1
common_init

QUERIES=(q1 q4 q5 q6 q12 q19)
OUT_DIR="./data/paper_runs/E6/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

echo "════════════════════════════════════════════════════════════"
echo "  E6: MPC Baseline — Party A (Alice, listener) on $(hostname)"
echo "  Queries:   ${QUERIES[*]}"
echo "  SF sweep:  ${SF_LIST}"
echo "  MPC bin:   ${MPC_BINARY}"
echo "  EMP port:  ${MPC_EMP_PORT}"
echo "════════════════════════════════════════════════════════════"

for SF in $SF_LIST; do
  DB_SIZE=$(sf_to_db "$SF")
  for Q in "${QUERIES[@]}"; do
    GF="${MPC_QUERY_FILTER[$Q]}"

    for RUN in $(seq 1 $REPS); do
      PREFIX="${OUT_DIR}/e6_mpc_${Q}_$(sf_label $SF)_run${RUN}"

      echo "[E6-A] MPC ${Q} $(sf_label $SF) run${RUN} — waiting for Bob to connect..."

      pkill -9 -f mpc_comparison_test 2>/dev/null || true
      sleep 2

      # Alice (party=1, listener)
      stdbuf -o0 -e0 "$MPC_BINARY" \
          --party=1 --port="$MPC_EMP_PORT" \
          --unioned_db="tpch_unioned_${DB_SIZE}" \
          --alice_db="tpch_alice_${DB_SIZE}" \
          --bob_db="tpch_bob_${DB_SIZE}" \
          --filter="${GF}" --validation=false \
          > "${PREFIX}_alice.log" 2>&1

      if grep -q '\[  PASSED  \] [1-9]' "${PREFIX}_alice.log" 2>/dev/null; then
          echo "    PASSED"
      else
          echo "    FAILED — check ${PREFIX}_alice.log"
      fi
    done
  done
  echo ""
done

echo "  E6 MPC Party A done."
