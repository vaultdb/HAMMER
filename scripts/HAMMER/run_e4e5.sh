#!/bin/bash
# run_e4e5.sh — Run E4 (base ablation) then E5 (SMT portability) continuously
# Both run as local 3-party loopback (no cross-server).
#
# Usage: bash scripts/HAMMER/run_e4e5.sh [--sf=1500] [--threads=16]
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "════════════════════════════════════════════════════════════"
echo "  Running E4 then E5 continuously"
echo "════════════════════════════════════════════════════════════"

bash "${SCRIPT_DIR}/run_e4.sh" "$@"

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  E4 complete. Starting E5..."
echo "════════════════════════════════════════════════════════════"
echo ""

bash "${SCRIPT_DIR}/run_e5.sh" "$@"

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  E4 + E5 complete."
echo "════════════════════════════════════════════════════════════"
