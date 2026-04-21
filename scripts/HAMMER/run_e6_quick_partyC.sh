#!/bin/bash
# run_e6_quick_partyC.sh — E6 SF-1 quick sweep: predicted-best config only
# 5 runs total. Start this AFTER Party B, BEFORE Party A.
# Usage: bash scripts/HAMMER/run_e6_quick_partyC.sh --alice_host=<A_IP>
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
common_init

if [ -z "$ALICE_HOST" ]; then
    echo "[ERROR] --alice_host=<ip> is required (IP for Party A)"
    exit 1
fi

SF=1
OUT_DIR="./data/paper_runs/E6_quick/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

# (query, config, threads) — MUST match partyB and partyA order!
declare -a RUNS=(
    "q19:new_H:$H"
)

echo "════════════════════════════════════════════════════════════"
echo "  E6 Quick: SF 1, predicted-best config — Party C on $(hostname)"
echo "  Party A on: ${ALICE_HOST}"
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

    echo "[E6-C] ${CFG} ${Q} $(sf_label $SF) OMP=${threads} — waiting for B and A..."

    pkill -9 -f fhe_tpch_test 2>/dev/null || true
    sleep 2

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

echo ""
echo "  E6 Quick Party C done."
