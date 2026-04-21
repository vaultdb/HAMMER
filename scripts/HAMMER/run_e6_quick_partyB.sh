#!/bin/bash
# run_e6_quick_partyB.sh — E6 SF-1 quick sweep: predicted-best config only
# 5 runs total (instead of 54):
#   Q4  new_H  (N=32768, d=12, OMP=H)  — confirmed winner at SF 1
#   Q5  new_P  (N=65536, d=14, OMP=P)  — predicted from SF 0.01/0.1
#   Q6  new_P  (N=65536, d=14, OMP=P)
#   Q12 new_P  (N=65536, d=14, OMP=P)
#   Q19 new_H  (N=65536, d=14, OMP=H)
#
# Start this FIRST, then Party C, then Party A.
# Usage: bash scripts/HAMMER/run_e6_quick_partyB.sh --charlie_host=<C_IP>
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
common_init

if [ -z "$CHARLIE_HOST" ]; then
    echo "[ERROR] --charlie_host=<ip> is required (IP for Party C)"
    exit 1
fi

SF=1
OUT_DIR="./data/paper_runs/E6_quick/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

# ── Results CSV ──────────────────────────────────────────────────
RESULTS_CSV="${OUT_DIR}/e6_quick_results.csv"
echo "query,sf,config,filter_ms,agg_ms,total_sec,status" > "$RESULTS_CSV"

# (query, config, threads) — order must match across all 3 party scripts!
declare -a RUNS=(
    "q19:new_H:$H"
)

echo "════════════════════════════════════════════════════════════"
echo "  E6 Quick: SF 1, predicted-best config — Party B on $(hostname)"
echo "  Party C on: ${CHARLIE_HOST}"
echo "  Runs:       ${#RUNS[@]}"
echo "  Threads:    P=${P}  H=${H}"
echo "════════════════════════════════════════════════════════════"

for RUN_SPEC in "${RUNS[@]}"; do
    IFS=: read -r Q CFG threads <<< "$RUN_SPEC"
    GF="${QUERY_FILTER[$Q]}"

    # new_H = auto threads (no override), new_P = force P
    case "$CFG" in
        new_P)  extra="--fhe_force_threads=$P" ;;
        new_H)  extra="" ;;
    esac

    PREFIX="${OUT_DIR}/e6_${CFG}_${Q}_$(sf_label $SF)"

    echo "[E6-B] ${CFG} ${Q} $(sf_label $SF) OMP=${threads} — waiting for C and A..."

    pkill -9 -f fhe_tpch_test 2>/dev/null || true
    sleep 2

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

    # Extract timing into CSV
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

echo ""
echo "  Results: ${RESULTS_CSV}"
echo ""
cat "$RESULTS_CSV" | column -t -s,
echo ""
echo "  E6 Quick Party B done."
