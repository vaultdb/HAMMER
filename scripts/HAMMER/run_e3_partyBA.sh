#!/bin/bash
# run_e3_partyBA.sh — E3 Party B + Party A (run on IIT/SPR)
# Party C must be started FIRST on codd via run_e3_partyC.sh
#
# Usage: bash scripts/HAMMER/run_e3_partyBA.sh --charlie_host=129.105.61.181
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
SF_LIST="${SF_LIST:-0.01}"
common_init

if [ -z "$CHARLIE_HOST" ]; then
    echo "[ERROR] --charlie_host=<codd_hostname_or_ip> is required"
    exit 1
fi
echo "  Party C host: ${CHARLIE_HOST}"

OUT_DIR="./data/paper_runs/E3/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

SORT_LIMITS=(64 256 1024 4096 8192)
GF="${QUERY_FILTER[sort_lineitem]}"

echo "════════════════════════════════════════════════════════════"
echo "  E3: SCS + MPC Sort (Party B + A on $(hostname))"
echo "  Party C on: ${CHARLIE_HOST}"
echo "  Sort limits: ${SORT_LIMITS[*]}, SF: ${SF_LIST}"
echo "════════════════════════════════════════════════════════════"

run_e3_cross() {
    local sf="$1" limit="$2" prefix="$3"

    pkill -9 -f fhe_tpch_test 2>/dev/null || true
    sleep 2

    local extra="--sort_limit=${limit} --fhe_force_threads=${P} --fhe_charlie_host=${CHARLIE_HOST}"

    # Party B (listens on 8765, connects to C for MPC)
    stdbuf -o0 -e0 env OMP_NUM_THREADS="$P" \
        "$FHE_BINARY" \
        --fhe_party=2 --party=2 \
        --fhe_port="$PORT_B" \
        --fhe_mpc_port="$MPC_PORT" \
        --fhe_charlie_host="$CHARLIE_HOST" \
        --unioned_db="tpch_unioned_$(sf_to_db $sf)" \
        --filter="${GF}" \
        --validation=true \
        --server_profile="$PROFILE_JSON" \
        $extra \
        > "${prefix}_party_b.log" 2>&1 &
    local pid_b=$!
    sleep 3

    # Party A (connects to B on localhost, C on charlie)
    stdbuf -o0 -e0 env OMP_NUM_THREADS="$P" \
        "$FHE_BINARY" \
        --fhe_party=1 --party=1 \
        --fhe_port="$PORT_B" \
        --fhe_charlie_port="$PORT_C" \
        --fhe_mpc_port="$MPC_PORT" \
        --fhe_bob_host=127.0.0.1 \
        --fhe_charlie_host="$CHARLIE_HOST" \
        --unioned_db="tpch_unioned_$(sf_to_db $sf)" \
        --filter="${GF}" \
        --validation=true \
        --server_profile="$PROFILE_JSON" \
        $extra \
        > "${prefix}_party_a.log" 2>&1 &
    local pid_a=$!

    set +e
    wait $pid_b $pid_a 2>/dev/null
    set -e

    if grep -q '\[  PASSED  \] [1-9]' "${prefix}_party_b.log" 2>/dev/null; then
        echo "    PASSED"
    else
        echo "    FAILED — check ${prefix}_party_b.log"
    fi
}

for SF in $SF_LIST; do
  for LIMIT in "${SORT_LIMITS[@]}"; do
    PREFIX="${OUT_DIR}/e3_sort_${LIMIT}_$(sf_label $SF)"
    if already_passed "$PREFIX"; then
        echo "[E3] sort_limit=${LIMIT} $(sf_label $SF) — SKIP (already passed)"
        continue
    fi

    echo "[E3] sort_limit=${LIMIT} $(sf_label $SF) T=${P}"
    run_e3_cross "$SF" "$LIMIT" "$PREFIX"
  done
  echo ""
done

# Timing breakdown
echo ""
echo "=== E3 Timing Breakdown ==="
printf "%-12s %12s %12s %12s\n" "sort_limit" "scs_ms" "sort_ms" "total_ms"
echo "----------------------------------------------------"
for LIMIT in "${SORT_LIMITS[@]}"; do
    LOG="${OUT_DIR}/e3_sort_${LIMIT}_$(sf_label $SF)_party_b.log"
    if [ ! -f "$LOG" ]; then
        printf "%-12s %12s %12s %12s\n" "$LIMIT" "N/A" "N/A" "N/A"
        continue
    fi
    scs_ms=$(grep -oP 'SecureContextSwitch ran for \K[0-9.]+' "$LOG" 2>/dev/null | head -1 || true)
    sort_ms=$(grep -oP 'Sort ran for \K[0-9.]+' "$LOG" 2>/dev/null | head -1 || true)
    scs_ms="${scs_ms:-N/A}"
    sort_ms="${sort_ms:-N/A}"
    if [[ "$scs_ms" != "N/A" && "$sort_ms" != "N/A" ]]; then
        total_ms=$(python3 -c "print(f'{${scs_ms} + ${sort_ms}:.3f}')" 2>/dev/null || echo "N/A")
    else
        total_ms="N/A"
    fi
    printf "%-12s %12s %12s %12s\n" "$LIMIT" "$scs_ms" "$sort_ms" "$total_ms"
done

parse_results "$OUT_DIR"
echo "  E3 Party B+A done."
