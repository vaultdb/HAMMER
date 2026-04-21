#!/bin/bash
# run_e7_partyBA.sh — E7 Scalability: Party B + A (run on IIT/SPR)
# Party C must be started FIRST on codd07 via run_e7_partyC.sh
#
# Usage: bash scripts/HAMMER/run_e7_partyBA.sh --charlie_host=129.105.61.181
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
SF_LIST="${SF_LIST:-0.1 1 10}"
REPS=1
common_init

if [ -z "$CHARLIE_HOST" ]; then
    echo "[ERROR] --charlie_host=<codd07_ip> is required"
    exit 1
fi
echo "  Party C host: ${CHARLIE_HOST}"

QUERIES=(q1 q4 q5 q6 q12 q19)
OUT_DIR="./data/paper_runs/E7/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

RESULTS_CSV="${OUT_DIR}/e7_results.csv"
if [ ! -f "$RESULTS_CSV" ]; then
    echo "mode,query,sf,run,filter_ms,agg_ms,total_sec,status" > "$RESULTS_CSV"
fi

echo "════════════════════════════════════════════════════════════"
echo "  E7: Scalability — Party B + A on $(hostname)"
echo "  Party C on: ${CHARLIE_HOST}"
echo "  Queries:    ${QUERIES[*]}"
echo "  SF sweep:   ${SF_LIST}"
echo "  Threads:    H=${H}"
echo "════════════════════════════════════════════════════════════"

run_e7_cross() {
    local sf="$1" gf="$2" prefix="$3"

    pkill -9 -f fhe_tpch_test 2>/dev/null || true
    sleep 2

    local start_ts
    start_ts=$(date +%s)

    # Party B (listens on PORT_B for A on localhost, connects to C)
    stdbuf -o0 -e0 env OMP_NUM_THREADS="$H" \
        "$FHE_BINARY" \
        --fhe_party=2 --party=2 \
        --fhe_port="$PORT_B" \
        --fhe_mpc_port="$MPC_PORT" \
        --fhe_charlie_host="$CHARLIE_HOST" \
        --unioned_db="tpch_unioned_$(sf_to_db $sf)" \
        --filter="${gf}" \
        --validation=true \
        --server_profile="$PROFILE_JSON" \
        > "${prefix}_party_b.log" 2>&1 &
    local pid_b=$!
    sleep 3

    # Party A (connects to B on localhost, connects to C)
    stdbuf -o0 -e0 env OMP_NUM_THREADS="$H" \
        "$FHE_BINARY" \
        --fhe_party=1 --party=1 \
        --fhe_port="$PORT_B" \
        --fhe_charlie_port="$PORT_C" \
        --fhe_mpc_port="$MPC_PORT" \
        --fhe_bob_host=127.0.0.1 \
        --fhe_charlie_host="$CHARLIE_HOST" \
        --unioned_db="tpch_unioned_$(sf_to_db $sf)" \
        --filter="${gf}" \
        --validation=true \
        --server_profile="$PROFILE_JSON" \
        > "${prefix}_party_a.log" 2>&1 &
    local pid_a=$!

    set +e
    wait $pid_b $pid_a 2>/dev/null
    set -e

    local end_ts
    end_ts=$(date +%s)
    local elapsed=$(( end_ts - start_ts ))

    if grep -q '\[  PASSED  \] [1-9]' "${prefix}_party_b.log" 2>/dev/null; then
        echo "    PASSED (${elapsed}s)"
    else
        echo "    FAILED (${elapsed}s) — check ${prefix}_party_b.log"
    fi
}

for SF in $SF_LIST; do
  for Q in "${QUERIES[@]}"; do
    GF="${QUERY_FILTER[$Q]}"

    for RUN in $(seq 1 $REPS); do
      PREFIX="${OUT_DIR}/e7_cpu_${Q}_$(sf_label $SF)_run${RUN}"

      if already_passed "$PREFIX"; then
          echo "[E7] ${Q} $(sf_label $SF) run${RUN} — SKIP (already passed)"
      else
          echo "[E7] ${Q} $(sf_label $SF) run${RUN}"
          run_e7_cross "$SF" "$GF" "$PREFIX"
      fi

      # Extract timing from Party B log
      local_log="${PREFIX}_party_b.log"
      status="FAILED"; filter_ms="0"; agg_ms="0"; total_sec="0"
      if [ -f "$local_log" ]; then
          if grep -q '\[  PASSED  \] [1-9]' "$local_log" 2>/dev/null; then
              status="PASSED"
          fi
          read -r filter_ms agg_ms total_sec <<< "$(extract_timing "$local_log")"
      fi
      echo "cpu,${Q},${SF},${RUN},${filter_ms},${agg_ms},${total_sec},${status}" >> "$RESULTS_CSV"
    done
  done
  echo ""
done

echo "  Results: ${RESULTS_CSV}"
echo ""
cat "$RESULTS_CSV" | column -t -s,
echo ""
echo "  E7 Party B+A done."
