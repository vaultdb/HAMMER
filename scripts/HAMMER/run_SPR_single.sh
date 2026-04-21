#!/bin/bash
# run_SPR_single.sh — E1, E2, E4 on single server (IIT/SPR, loopback)
# All 3 parties on the same machine.
#
# Usage: bash scripts/HAMMER/run_SPR_single.sh [--sf=15000] [--dry-run]
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "════════════════════════════════════════════════════════════"
echo "  HAMMER Paper Experiments — Single Server (E1, E2, E4)"
echo "  Args: $*"
echo "════════════════════════════════════════════════════════════"

bash "${SCRIPT_DIR}/run_e1.sh" "$@"
echo ""

bash "${SCRIPT_DIR}/run_e2.sh" "$@"
echo ""

bash "${SCRIPT_DIR}/run_e4.sh" "$@"
echo ""

echo "════════════════════════════════════════════════════════════"
echo "  All single-server experiments (E1, E2, E4) done."
echo "════════════════════════════════════════════════════════════"
