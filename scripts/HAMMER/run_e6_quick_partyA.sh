#!/bin/bash
# run_e6_quick_partyA.sh — E6 SF-1 quick sweep: predicted-best config only
# 5 runs total. Start this LAST, after Party B and Party C.
# Usage: bash scripts/HAMMER/run_e6_quick_partyA.sh --bob_host=<B_IP> --charlie_host=<C_IP>
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
common_init

if [ -z "$BOB_HOST" ]; then
    echo "[ERROR] --bob_host=<ip> is required (IP for Party B)"
    exit 1
fi
if [ -z "$CHARLIE_HOST" ]; then
    echo "[ERROR] --charlie_host=<ip> is required (IP for Party C)"
    exit 1
fi

SF=1
OUT_DIR="./data/paper_runs/E6_quick/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

# (query, config, threads) — MUST match partyB and partyC order!
declare -a RUNS=(
    "q19:new_H:$H"
)

echo "════════════════════════════════════════════════════════════"
echo "  E6 Quick: SF 1, predicted-best config — Party A on $(hostname)"
echo "  Party B on: ${BOB_HOST}"
echo "  Party C on: ${CHARLIE_HOST}"
echo "  Runs:       ${#RUNS[@]}"
echo "  Threads:    P=${P}  H=${H}"
echo "════════════════════════════════════════════════════════════"

for RUN_SPEC in "${RUNS[@]}"; do
    IFS=: read -r Q CFG threads <<< "$RUN_SPEC"
    GF="${QUERY_FILTER[$Q]}"

    case "$CFG" in
        new_P)  extra="--fhe_force_threads=$P" ;;
        new_H)  extra="" ;;
    esac

    PREFIX="${OUT_DIR}/e6_${CFG}_${Q}_$(sf_label $SF)"

    echo "[E6-A] ${CFG} ${Q} $(sf_label $SF) OMP=${threads} — connecting to B and C..."

    pkill -9 -f fhe_tpch_test 2>/dev/null || true
    sleep 2

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

echo ""
echo "  E6 Quick Party A done."
