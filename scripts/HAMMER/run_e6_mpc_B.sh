#!/bin/bash
# run_e6_mpc_B.sh — E6 MPC Baseline: Party B / Bob (party=2, connector)
# Start this AFTER Party A (Alice) is already listening.
#
# Usage: bash scripts/HAMMER/run_e6_mpc_B.sh --alice_host=129.105.61.181 [--sf="0.01 0.1"]
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

MPC_BINARY="${MPC_BINARY:-./bin/mpc_comparison_test}"

ALICE_HOST=""
for arg in "$@"; do
    case "$arg" in
        --alice_host=*) ALICE_HOST="${arg#*=}" ;;
    esac
done
parse_common_args "$@"
SF_LIST="${SF_LIST:-0.01 0.1}"
REPS=1
common_init

if [ -z "$ALICE_HOST" ]; then
    echo "[ERROR] --alice_host=<ip> is required (IP of machine running Party A)"
    exit 1
fi

QUERIES=(q1 q4 q5 q6 q12 q19)
OUT_DIR="./data/paper_runs/E6/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

RESULTS_CSV="${OUT_DIR}/e6_mpc_results.csv"
if [ ! -f "$RESULTS_CSV" ]; then
    echo "query,sf,run,filter_ms,agg_ms,total_sec,status" > "$RESULTS_CSV"
fi

echo "════════════════════════════════════════════════════════════"
echo "  E6: MPC Baseline — Party B (Bob, connector) on $(hostname)"
echo "  Party A on: ${ALICE_HOST}"
echo "  Queries:    ${QUERIES[*]}"
echo "  SF sweep:   ${SF_LIST}"
echo "  MPC bin:    ${MPC_BINARY}"
echo "  EMP port:   ${MPC_EMP_PORT}"
echo "════════════════════════════════════════════════════════════"

for SF in $SF_LIST; do
  DB_SIZE=$(sf_to_db "$SF")
  for Q in "${QUERIES[@]}"; do
    GF="${MPC_QUERY_FILTER[$Q]}"

    for RUN in $(seq 1 $REPS); do
      PREFIX="${OUT_DIR}/e6_mpc_${Q}_$(sf_label $SF)_run${RUN}"

      echo "[E6-B] MPC ${Q} $(sf_label $SF) run${RUN} — connecting to Alice at ${ALICE_HOST}..."

      pkill -9 -f mpc_comparison_test 2>/dev/null || true
      sleep 2

      local_start=$(date +%s)

      # Bob (party=2, connector)
      stdbuf -o0 -e0 "$MPC_BINARY" \
          --party=2 --port="$MPC_EMP_PORT" \
          --alice_host="$ALICE_HOST" \
          --unioned_db="tpch_unioned_${DB_SIZE}" \
          --alice_db="tpch_alice_${DB_SIZE}" \
          --bob_db="tpch_bob_${DB_SIZE}" \
          --filter="${GF}" --validation=false \
          > "${PREFIX}_bob.log" 2>&1

      local_end=$(date +%s)
      elapsed=$(( local_end - local_start ))

      if grep -q '\[  PASSED  \] [1-9]' "${PREFIX}_bob.log" 2>/dev/null; then
          echo "    PASSED (${elapsed}s)"
          status="PASSED"
      else
          echo "    FAILED (${elapsed}s) — check ${PREFIX}_bob.log"
          status="FAILED"
      fi

      # Extract timing from Bob log
      filter_ms=$(grep -oP 'Operator #1 Filter ran for \K[0-9.]+' "${PREFIX}_bob.log" 2>/dev/null | head -1 || echo "0")
      agg_ms=$(grep -oP 'Operator #2 SortMergeAggregate ran for \K[0-9.]+' "${PREFIX}_bob.log" 2>/dev/null | head -1 || echo "0")
      echo "${Q},${SF},${RUN},${filter_ms},${agg_ms},${elapsed},${status}" >> "$RESULTS_CSV"
    done
  done
  echo ""
done

echo "  Results: ${RESULTS_CSV}"
echo ""
cat "$RESULTS_CSV" | column -t -s,
echo ""
echo "  E6 MPC Party B done."
