#!/bin/bash
set -euo pipefail
#
# entrypoint.sh — Docker entrypoint for VaultDB HAMMER experiments
#
# Usage:
#   docker run --network=host vaultdb:latest \
#       --party=2 --sf=0.1 --s3_bucket=hammer-tpch-dataset-956978447815-us-east-2-an \
#       --server_profile=profiles/server_profile_g5_16xlarge.json \
#       -- --filter="*q1*" --validation=true

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
PARTY=""
SF="0.1"
S3_BUCKET="hammer-tpch-dataset-956978447815-us-east-2-an"
BOB_HOST="127.0.0.1"
CHARLIE_HOST="127.0.0.1"
SERVER_PROFILE=""
BINARY="fhe_tpch_test"
EXTRA_FLAGS=""

# ---------------------------------------------------------------------------
# sf_to_db (matches common.sh)
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
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --party=*)          PARTY="${1#*=}"; shift ;;
        --sf=*)             SF="${1#*=}"; shift ;;
        --s3_bucket=*)      S3_BUCKET="${1#*=}"; shift ;;
        --bob_host=*)       BOB_HOST="${1#*=}"; shift ;;
        --charlie_host=*)   CHARLIE_HOST="${1#*=}"; shift ;;
        --server_profile=*) SERVER_PROFILE="${1#*=}"; shift ;;
        --binary=*)         BINARY="${1#*=}"; shift ;;
        --)                 shift; EXTRA_FLAGS="$*"; break ;;
        *)                  EXTRA_FLAGS="${EXTRA_FLAGS} $1"; shift ;;
    esac
done

if [[ -z "$PARTY" ]]; then
    echo "[ERROR] --party=N is required (1=A, 2=B, 3=C)"
    exit 1
fi

DB_SIZE=$(sf_to_db "$SF")
echo "========================================"
echo "  VaultDB HAMMER — Party ${PARTY}"
echo "  Binary: ${BINARY}"
echo "  SF=${SF}  DB_SIZE=${DB_SIZE}"
echo "  BOB_HOST=${BOB_HOST}"
echo "  CHARLIE_HOST=${CHARLIE_HOST}"
echo "========================================"

# ---------------------------------------------------------------------------
# 1. Start PostgreSQL (all parties — A needs DB for validation)
# ---------------------------------------------------------------------------
echo "[entrypoint] Starting PostgreSQL..."
sudo -u postgres pg_ctlcluster 16 main start

# Create vaultdb role if missing
sudo -u postgres psql -c "CREATE ROLE vaultdb WITH LOGIN SUPERUSER;" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 2. Load data from S3 (all parties, skip if DB exists)
#    Party A needs the unioned DB for validation queries.
#    Party B and C need unioned + alice/bob.
# ---------------------------------------------------------------------------
if ! psql -U vaultdb -lqt 2>/dev/null | grep -qw "tpch_unioned_${DB_SIZE}"; then
    echo "[entrypoint] Downloading data from S3..."
    mkdir -p /tmp/tpch_data
    aws s3 cp "s3://${S3_BUCKET}/tpch_data/sf_${SF}/" /tmp/tpch_data/ --recursive

    for dump in /tmp/tpch_data/*.sql.gz; do
        db=$(basename "$dump" .sql.gz)
        echo "[entrypoint] Loading database: $db"
        createdb -U vaultdb "$db" 2>/dev/null || true
        gunzip -c "$dump" | psql -U vaultdb "$db" -q
    done
    rm -rf /tmp/tpch_data
    echo "[entrypoint] Data loaded."
else
    echo "[entrypoint] Database tpch_unioned_${DB_SIZE} already exists, skipping load."
fi

# ---------------------------------------------------------------------------
# 3. Build server profile args
# ---------------------------------------------------------------------------
PROFILE_ARG=""
if [[ -n "$SERVER_PROFILE" ]]; then
    PROFILE_ARG="--server_profile=${SERVER_PROFILE}"
fi

# ---------------------------------------------------------------------------
# 4. Run test binary
# ---------------------------------------------------------------------------
echo "[entrypoint] Starting ${BINARY}..."
exec ./bin/${BINARY} \
    --fhe_party="$PARTY" \
    --party="$PARTY" \
    --unioned_db="tpch_unioned_${DB_SIZE}" \
    --fhe_bob_host="${BOB_HOST}" \
    --fhe_charlie_host="${CHARLIE_HOST}" \
    $PROFILE_ARG \
    $EXTRA_FLAGS
