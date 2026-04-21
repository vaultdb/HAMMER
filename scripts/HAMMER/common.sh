#!/bin/bash
# common.sh — Shared helpers for HAMMER paper experiment scripts
# Source this from each run_eN.sh script.
# ════════════════════════════════════════════════════════════════

# ---------------------------------------------------------------------------
# Configuration (overridable via environment)
# ---------------------------------------------------------------------------
FHE_BINARY="${FHE_BINARY:-./bin/fhe_tpch_test}"
GPU_BINARY="${GPU_BINARY:-./bin/gpu_fhe_tpch_test}"
MPC_BINARY="${MPC_BINARY:-./bin/mpc_comparison_test}"
MPC_EMP_PORT="${MPC_EMP_PORT:-54345}"
PORT_B="${PORT_B:-8765}"
PORT_C="${PORT_C:-8766}"
MPC_PORT="${MPC_PORT:-8777}"
DRY_RUN=false
SERVER_NAME=""
SF_LIST=""

# ---------------------------------------------------------------------------
# sf_to_db: Maps SF value (CLI) to DB size for tpch_unioned_N
#   0.001 → 150,  0.01 → 1500,  0.1 → 15000
# ---------------------------------------------------------------------------
sf_to_db() {
    case "$1" in
        0.001) echo "150"     ;;
        0.01)  echo "1500"    ;;
        0.1)   echo "15000"   ;;
        1)     echo "150000"  ;;
        10)    echo "1500000" ;;
        *)     echo "$1"      ;;
    esac
}

# ---------------------------------------------------------------------------
# sf_label: Maps SF value to file name label
#   0.001 → sf_0.001,  0.01 → sf_0.01,  0.1 → sf_0.1
# ---------------------------------------------------------------------------
sf_label() {
    echo "sf_$1"
}

# Query → gtest filter mapping (CPU binary: fhe_tpch_test)
declare -A QUERY_FILTER=(
    [q1]="FheTpchTest.fhe_tpch_q1"
    [q1_one_sum]="FheTpchTest.fhe_tpch_q1_one_sum"
    [sort_lineitem]="FheTpchTest.fhe_tpch_sort_lineitem"
    [q3]="*fhe_tpch_q3*"
    [q4]="*fhe_tpch_q4*"
    [q5]="*fhe_tpch_q5*"
    [q6]="*fhe_tpch_q6*"
    [q12]="*fhe_tpch_q12*"
    [q19]="*fhe_tpch_q19*"
)

# Query → gtest filter mapping (GPU binary: gpu_fhe_tpch_test)
declare -A GPU_QUERY_FILTER=(
    [q1]="GpuFheTpchTest.fhe_tpch_q1"
    [q4]="GpuFheTpchTest.fhe_tpch_q4"
    [q5]="GpuFheTpchTest.fhe_tpch_q5"
    [q6]="GpuFheTpchTest.fhe_tpch_q6"
    [q12]="GpuFheTpchTest.fhe_tpch_q12"
    [q19]="GpuFheTpchTest.fhe_tpch_q19"
)

# Query → gtest filter mapping (MPC binary: mpc_comparison_test)
declare -A MPC_QUERY_FILTER=(
    [q1]="MpcComparisonTest.tpch_q01"
    [q4]="MpcComparisonTest.tpch_q04"
    [q5]="MpcComparisonTest.tpch_q05"
    [q6]="MpcComparisonTest.tpch_q06"
    [q12]="MpcComparisonTest.tpch_q12"
    [q19]="MpcComparisonTest.tpch_q19"
)

# ---------------------------------------------------------------------------
# parse_common_args: Parse --dry-run, --server=, --sf= from "$@"
# ---------------------------------------------------------------------------
parse_common_args() {
    for arg in "$@"; do
        case "$arg" in
            --server=*)       SERVER_NAME="${arg#*=}" ;;
            --sf=*)           SF_LIST="${arg#*=}" ;;
            --dry-run)        DRY_RUN=true ;;
            --bob_host=*|--charlie_host=*|--alice_host=*|--binary=*)
                ;;  # handled by caller
        esac
    done
}

# ---------------------------------------------------------------------------
# detect_hardware: Sets P, H, L3_BYTES, L3_MB, SERVER_NAME
# ---------------------------------------------------------------------------
detect_hardware() {
    # Physical cores = unique (physical_id, core_id) pairs
    P=$(awk '
        /^physical id/ { phys=$NF }
        /^core id/     { core=$NF; seen[phys","core]++ }
        END            { print length(seen) }
    ' /proc/cpuinfo 2>/dev/null || echo 0)

    # Logical cores = number of processor entries
    H=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || nproc 2>/dev/null || echo 12)

    if (( P == 0 )); then P=$H; fi

    # L3 cache: sum all unique L3 instances across sockets/CCXs.
    # Each CPU's sysfs reports its own L3 slice; shared_cpu_list tells us
    # which CPUs share the same instance. We collect one entry per unique
    # shared_cpu_list to avoid double-counting.
    L3_BYTES=0
    L3_IDX=""
    for idx in $(seq 0 15); do
        base="/sys/devices/system/cpu/cpu0/cache/index${idx}"
        [ -f "${base}/level" ] || break
        level=$(cat "${base}/level" 2>/dev/null || echo 0)
        if [ "$level" = "3" ]; then
            L3_IDX="$idx"
            break
        fi
    done

    if [ -n "$L3_IDX" ]; then
        # Collect unique L3 instances by their shared_cpu_list
        declare -A seen_l3
        for cpudir in /sys/devices/system/cpu/cpu[0-9]*/cache/index${L3_IDX}; do
            [ -f "$cpudir/shared_cpu_list" ] || continue
            key=$(cat "$cpudir/shared_cpu_list" 2>/dev/null || true)
            [ -n "$key" ] || continue
            if [ -z "${seen_l3[$key]+x}" ]; then
                seen_l3[$key]=1
                raw=$(cat "$cpudir/size" 2>/dev/null || echo "0K")
                num=$(echo "$raw" | sed 's/[^0-9]//g')
                unit=$(echo "$raw" | sed 's/[0-9]//g')
                case "$unit" in
                    K) L3_BYTES=$((L3_BYTES + num * 1024)) ;;
                    M) L3_BYTES=$((L3_BYTES + num * 1024 * 1024)) ;;
                    *) L3_BYTES=$((L3_BYTES + num)) ;;
                esac
            fi
        done
    fi

    if (( L3_BYTES == 0 )); then
        L3_BYTES=15728640  # fallback: 15MB
        echo "  WARNING: Could not detect L3 cache, using default 15MB"
    fi

    L3_MB=$((L3_BYTES / 1024 / 1024))

    # Server name: auto-detect from hostname if not provided
    if [ -z "$SERVER_NAME" ]; then
        SERVER_NAME="$(hostname | cut -d. -f1)"
    fi

    echo "  Server:   ${SERVER_NAME}"
    echo "  Physical: P=${P}"
    echo "  Logical:  H=${H}"
    echo "  L3 cache: ${L3_MB}MB (${L3_BYTES} bytes)"
}

# ---------------------------------------------------------------------------
# generate_profile: Creates server_profile_${SERVER_NAME}.json
# ---------------------------------------------------------------------------
generate_profile() {
    PROFILE_DIR="./profiles"
    mkdir -p "$PROFILE_DIR"
    PROFILE_JSON="${PROFILE_DIR}/server_profile_${SERVER_NAME}.json"

    cat > "$PROFILE_JSON" << PROF_EOF
{
  "hostname": "${SERVER_NAME}",
  "physical_cores": ${P},
  "logical_cores": ${H},
  "l3_cache_bytes": ${L3_BYTES},
  "pi_spill": 2.0,
  "gamma_spill": 1.0,
  "over_thread_alpha": 0.05
}
PROF_EOF

    echo "  Profile:  ${PROFILE_JSON}"
}

# ---------------------------------------------------------------------------
# preflight_check: Verifies binary exists
# ---------------------------------------------------------------------------
preflight_check() {
    if [[ "$DRY_RUN" == false && ! -x "$FHE_BINARY" ]]; then
        echo "[ERROR] Binary not found: $FHE_BINARY"
        echo "  Run 'make -j4' first."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# cleanup_all: Kills stale processes, frees ports
# ---------------------------------------------------------------------------
cleanup_all() {
    echo "[cleanup] Killing all fhe_tpch_test processes..."
    pkill -9 -f fhe_tpch_test 2>/dev/null || true

    # Force-kill port holders
    for p in "$PORT_B" "$PORT_C" "$MPC_PORT"; do
        fuser -k -9 "${p}/tcp" 2>/dev/null || true
    done

    # Wait until ALL processes are dead (max 30s)
    local waited=0
    while pgrep -f fhe_tpch_test > /dev/null 2>&1; do
        if [ ${waited} -ge 30 ]; then
            echo "[cleanup] WARNING: processes still alive after 30s"
            break
        fi
        sleep 1; waited=$((waited + 1))
    done

    # Wait until ALL ports are free (max 30s)
    waited=0
    while fuser ${PORT_B}/tcp ${PORT_C}/tcp ${MPC_PORT}/tcp \
          > /dev/null 2>&1; do
        if [ ${waited} -ge 30 ]; then
            echo "[cleanup] WARNING: ports still occupied after 30s"
            break
        fi
        sleep 1; waited=$((waited + 1))
    done

    echo "[cleanup] Done."
}

# ---------------------------------------------------------------------------
# already_passed: Returns 0 if ${prefix}_party_b.log contains PASSED
# ---------------------------------------------------------------------------
already_passed() {
    local prefix="$1"
    local log_b="${prefix}_party_b.log"
    if [ -f "$log_b" ] && grep -q '\[  PASSED  \] [1-9]' "$log_b" 2>/dev/null; then
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# run_3party: B→sleep 3→C→sleep 8→A, captures logs
#   $1=sf $2=gtest_filter $3=omp_threads $4=log_prefix $5=extra_flags
# ---------------------------------------------------------------------------
run_3party() {
    local sf="$1" gf="$2" threads="$3" prefix="$4"
    local extra="${5:-}"

    local log_b="${prefix}_party_b.log"
    local log_c="${prefix}_party_c.log"
    local log_a="${prefix}_party_a.log"

    if [[ "$DRY_RUN" == true ]]; then
        echo "    (dry-run) OMP=${threads} 3-party: B→C→A, filter=${gf} ${extra}"
        return 0
    fi

    cleanup_all

    local start_ts
    start_ts=$(date +%s)

    # Party B (server, listens first)
    stdbuf -o0 -e0 env OMP_NUM_THREADS="$threads" \
        "$FHE_BINARY" \
        --fhe_party=2 --party=2 \
        --fhe_port="$PORT_B" \
        --fhe_mpc_port="$MPC_PORT" \
        --unioned_db="tpch_unioned_$(sf_to_db $sf)" \
        --filter="${gf}" \
        --validation=true \
        --server_profile="$PROFILE_JSON" \
        $extra \
        > "$log_b" 2>&1 &
    local pid_b=$!
    sleep 3

    # Party C
    stdbuf -o0 -e0 env OMP_NUM_THREADS="$threads" \
        "$FHE_BINARY" \
        --fhe_party=3 --party=3 \
        --fhe_charlie_port="$PORT_C" \
        --fhe_mpc_port="$MPC_PORT" \
        --unioned_db="tpch_unioned_$(sf_to_db $sf)" \
        --filter="${gf}" \
        --validation=true \
        --server_profile="$PROFILE_JSON" \
        $extra \
        > "$log_c" 2>&1 &
    local pid_c=$!
    sleep 8

    # Party A (connects to both B and C)
    stdbuf -o0 -e0 env OMP_NUM_THREADS="$threads" \
        "$FHE_BINARY" \
        --fhe_party=1 --party=1 \
        --fhe_port="$PORT_B" \
        --fhe_charlie_port="$PORT_C" \
        --fhe_mpc_port="$MPC_PORT" \
        --unioned_db="tpch_unioned_$(sf_to_db $sf)" \
        --filter="${gf}" \
        --validation=true \
        --server_profile="$PROFILE_JSON" \
        $extra \
        > "$log_a" 2>&1 &
    local pid_a=$!

    set +e
    wait $pid_a $pid_b $pid_c 2>/dev/null
    local rc=$?
    set -e

    local end_ts
    end_ts=$(date +%s)
    local elapsed=$(( end_ts - start_ts ))

    # Check pass/fail from Party B log
    if grep -q '\[  PASSED  \] [1-9]' "$log_b" 2>/dev/null; then
        echo "    PASSED (${elapsed}s)"
    else
        echo "    FAILED (${elapsed}s) — check ${log_b}"
    fi
}

# ---------------------------------------------------------------------------
# run_gpu_single: Single-process GPU filter run (no 3-party setup needed)
#   $1=sf  $2=gtest_filter  $3=log_prefix  $4=extra_flags
#   Writes to ${prefix}_party_b.log for E6 parsing compatibility.
# ---------------------------------------------------------------------------
run_gpu_single() {
    local sf="$1" gf="$2" prefix="$3"
    local extra="${4:-}"

    local log="${prefix}_party_b.log"

    if [[ "$DRY_RUN" == true ]]; then
        echo "    (dry-run) GPU single: ${GPU_BINARY} filter=${gf} ${extra}"
        return 0
    fi

    if [[ ! -x "$GPU_BINARY" ]]; then
        echo "[ERROR] GPU binary not found: $GPU_BINARY"
        return 1
    fi

    local start_ts
    start_ts=$(date +%s)

    stdbuf -o0 -e0 \
        "$GPU_BINARY" \
        --unioned_db="tpch_unioned_$(sf_to_db $sf)" \
        --filter="${gf}" \
        --validation=true \
        $extra \
        > "$log" 2>&1
    local rc=$?

    local end_ts
    end_ts=$(date +%s)
    local elapsed=$(( end_ts - start_ts ))

    if grep -q '\[  PASSED  \] [1-9]' "$log" 2>/dev/null; then
        echo "    PASSED (${elapsed}s)"
    else
        echo "    FAILED (${elapsed}s) — check ${log}"
    fi
    return $rc
}

# ---------------------------------------------------------------------------
# cleanup_mpc: Kills stale secure_tpch_test processes, frees EMP port
# ---------------------------------------------------------------------------
cleanup_mpc() {
    pkill -9 -f mpc_comparison_test 2>/dev/null || true
    fuser -k -9 "${MPC_EMP_PORT}/tcp" 2>/dev/null || true
    local waited=0
    while pgrep -f mpc_comparison_test > /dev/null 2>&1; do
        if [ ${waited} -ge 15 ]; then break; fi
        sleep 1; waited=$((waited + 1))
    done
}

# ---------------------------------------------------------------------------
# run_2party_mpc: Alice (party=1) + Bob (party=2) via secure_tpch_test
#   $1=sf  $2=gtest_filter  $3=log_prefix  $4=extra_flags
#   Writes ${prefix}_alice.log and ${prefix}_bob.log.
# ---------------------------------------------------------------------------
run_2party_mpc() {
    local sf="$1" gf="$2" prefix="$3"
    local extra="${4:-}"
    local db_size
    db_size=$(sf_to_db "$sf")

    local log_a="${prefix}_alice.log"
    local log_b="${prefix}_bob.log"

    if [[ "$DRY_RUN" == true ]]; then
        echo "    (dry-run) MPC 2-party: A+B, filter=${gf} ${extra}"
        return 0
    fi

    if [[ ! -x "$MPC_BINARY" ]]; then
        echo "[ERROR] MPC binary not found: $MPC_BINARY"
        return 1
    fi

    cleanup_mpc

    local start_ts
    start_ts=$(date +%s)

    # Alice (party=1, listener)
    stdbuf -o0 -e0 "$MPC_BINARY" \
        --party=1 --port="$MPC_EMP_PORT" \
        --unioned_db="tpch_unioned_${db_size}" \
        --alice_db="tpch_alice_${db_size}" \
        --bob_db="tpch_bob_${db_size}" \
        --filter="${gf}" --validation=false \
        $extra \
        > "$log_a" 2>&1 &
    local pid_a=$!
    sleep 2

    # Bob (party=2, connector)
    stdbuf -o0 -e0 "$MPC_BINARY" \
        --party=2 --port="$MPC_EMP_PORT" \
        --unioned_db="tpch_unioned_${db_size}" \
        --alice_db="tpch_alice_${db_size}" \
        --bob_db="tpch_bob_${db_size}" \
        --filter="${gf}" --validation=false \
        $extra \
        > "$log_b" 2>&1 &
    local pid_b=$!

    set +e
    wait $pid_a $pid_b 2>/dev/null
    local rc=$?
    set -e

    local end_ts
    end_ts=$(date +%s)
    local elapsed=$(( end_ts - start_ts ))

    if grep -q '\[  PASSED  \] [1-9]' "$log_a" 2>/dev/null; then
        echo "    PASSED (${elapsed}s)"
    else
        echo "    FAILED (${elapsed}s) — check ${log_a}"
    fi
    return $rc
}

# ---------------------------------------------------------------------------
# mpc_already_passed: Returns 0 if ${prefix}_alice.log contains PASSED
# ---------------------------------------------------------------------------
mpc_already_passed() {
    local prefix="$1"
    local log="${prefix}_alice.log"
    if [ -f "$log" ] && grep -q '\[  PASSED  \] [1-9]' "$log" 2>/dev/null; then
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# extract_timing: Extract operator-level timing from a party_b log
#   Returns: filter_ms agg_ms total_sec (space-separated, 0 if not found)
# ---------------------------------------------------------------------------
extract_timing() {
    local log="$1"
    local filter_ms agg_ms total_sec

    filter_ms=$(grep -oP '\[Timing\] Operator #1 \(FheFilter\).*?([0-9]+\.[0-9]+) ms' "$log" 2>/dev/null \
        | grep -oP '[0-9]+\.[0-9]+ ms' | head -1 | grep -oP '[0-9]+\.[0-9]+' || echo "0")
    agg_ms=$(grep -oP '\[Timing\] Operator #2 \(FheAggregate\).*?([0-9]+\.[0-9]+) ms' "$log" 2>/dev/null \
        | grep -oP '[0-9]+\.[0-9]+ ms' | head -1 | grep -oP '[0-9]+\.[0-9]+' || echo "0")
    total_sec=$(grep -oP 'Runtime[^:]*:\s*\K[0-9.]+' "$log" 2>/dev/null | head -1 || echo "0")

    echo "${filter_ms} ${agg_ms} ${total_sec}"
}

# ---------------------------------------------------------------------------
# run_3party_with_timeout: Wrapper around run_3party with a timeout (seconds)
#   $1=timeout_sec $2..=run_3party args
# ---------------------------------------------------------------------------
run_3party_with_timeout() {
    local timeout_sec="$1"; shift

    if [[ "$DRY_RUN" == true ]]; then
        run_3party "$@"
        return 0
    fi

    # Run 3party in a subshell with timeout
    local rc=0
    timeout --signal=KILL "$timeout_sec" bash -c "
        source '${SCRIPT_DIR}/common.sh'
        PROFILE_JSON='$PROFILE_JSON'
        DRY_RUN=false
        run_3party $*
    " || rc=$?

    if [ $rc -eq 137 ]; then
        echo "    TIMEOUT after ${timeout_sec}s"
    fi
    return $rc
}

# ---------------------------------------------------------------------------
# parse_results: Extract timing from party_b logs in a directory → CSV
# ---------------------------------------------------------------------------
parse_results() {
    local dir="$1"
    local csv="${dir}/results.csv"
    echo "experiment,query,config,ring_dim,threads,runtime_sec,status" > "$csv"

    for log in "${dir}"/*_party_b.log; do
        [ -f "$log" ] || continue
        local basename
        basename="$(basename "$log" _party_b.log)"

        local status="FAILED"
        if grep -q '\[  PASSED  \] [1-9]' "$log" 2>/dev/null; then
            status="PASSED"
        fi

        local runtime
        runtime=$(grep -oP 'Runtime[^:]*:\s*\K[0-9.]+' "$log" 2>/dev/null | head -1 || true)
        runtime="${runtime:-0}"

        local ring_dim
        ring_dim=$(grep -oP 'ring_dim=\K[0-9]+' "$log" 2>/dev/null | head -1 || true)
        ring_dim="${ring_dim:-0}"

        local threads
        threads=$(grep -oP 'max_threads=\K[0-9]+' "$log" 2>/dev/null | head -1 || true)
        threads="${threads:-0}"

        echo "${basename},,${basename},${ring_dim},${threads},${runtime},${status}" >> "$csv"
    done

    echo "  Results: ${csv}"
}

# ---------------------------------------------------------------------------
# S3 data loading configuration
# ---------------------------------------------------------------------------
S3_BUCKET="${S3_BUCKET:-hammer-tpch-dataset-956978447815-us-east-2-an}"
S3_REGION="${S3_REGION:-us-east-2}"
DB_USER="${DB_USER:-vaultdb}"

# ---------------------------------------------------------------------------
# ensure_pg_running: Start PostgreSQL if not running, create vaultdb role
# ---------------------------------------------------------------------------
ensure_pg_running() {
    if ! pg_isready -q 2>/dev/null; then
        echo "[data] Starting PostgreSQL..."
        if command -v pg_ctlcluster >/dev/null 2>&1; then
            sudo -u postgres pg_ctlcluster 16 main start 2>/dev/null || \
            sudo -u postgres pg_ctlcluster 14 main start 2>/dev/null || true
        else
            sudo -u postgres pg_ctl start -D /var/lib/postgresql/data 2>/dev/null || true
        fi
        sleep 2
    fi
    # Create vaultdb role if missing
    sudo -u postgres psql -c "CREATE ROLE ${DB_USER} WITH LOGIN SUPERUSER;" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# ensure_data_loaded: Load TPC-H data from S3 for given SF list
#   $1 = space-separated SF values (e.g., "0.01 0.1 1 10")
# ---------------------------------------------------------------------------
ensure_data_loaded() {
    local sf_list="$1"
    ensure_pg_running

    for sf in $sf_list; do
        local db_size
        db_size=$(sf_to_db "$sf")
        local db_name="tpch_unioned_${db_size}"

        if psql -U "$DB_USER" -lqt 2>/dev/null | grep -qw "$db_name"; then
            echo "[data] ${db_name} (SF ${sf}) already loaded — skip"
            continue
        fi

        echo "[data] Downloading SF ${sf} from s3://${S3_BUCKET}/tpch_data/sf_${sf}/ ..."
        local tmp_dir="/tmp/tpch_data_sf_${sf}"
        mkdir -p "$tmp_dir"
        aws s3 cp "s3://${S3_BUCKET}/tpch_data/sf_${sf}/" "$tmp_dir/" --recursive --region "$S3_REGION"

        for dump in "${tmp_dir}"/*.sql.gz; do
            [ -f "$dump" ] || continue
            local db
            db=$(basename "$dump" .sql.gz)
            echo "[data] Loading database: ${db}"
            createdb -U "$DB_USER" "$db" 2>/dev/null || true
            gunzip -c "$dump" | psql -U "$DB_USER" "$db" -q
        done
        rm -rf "$tmp_dir"
        echo "[data] SF ${sf} loaded."
    done
}

# ---------------------------------------------------------------------------
# common_init: detect_hardware + generate_profile + preflight_check + trap
# ---------------------------------------------------------------------------
common_init() {
    echo "════════════════════════════════════════════════════════════"
    echo "  HAMMER Paper Experiments — Hardware Detection"
    echo "════════════════════════════════════════════════════════════"
    detect_hardware
    echo ""
    generate_profile
    echo "════════════════════════════════════════════════════════════"
    echo ""
    preflight_check
    trap cleanup_all EXIT
}
