#!/bin/bash
# run_all.sh — Orchestrator for all HAMMER paper experiments
# Priority order: E1 → E2 → E5 → E4 → E7 → E3 → E6
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "════════════════════════════════════════════════════════════"
echo "  HAMMER Paper Experiments — Full Suite"
echo "  Args: $*"
echo "════════════════════════════════════════════════════════════"
echo ""

run_experiment() {
    local name="$1"
    local script="$2"
    shift 2
    echo "┌──────────────────────────────────────────────────────────┐"
    echo "│  Running ${name}                                        │"
    echo "└──────────────────────────────────────────────────────────┘"
    bash "${SCRIPT_DIR}/${script}" "$@"
    echo ""
}

# Priority order: core results first, then supporting experiments
run_experiment "E1: Selective vs All-Column"       run_e1.sh "$@"
run_experiment "E2: End-to-End vs Engorgio"      run_e2.sh "$@"
run_experiment "E5: SMT Policy Portability"       run_e5.sh "$@"
run_experiment "E4: Comparator Base Ablation"      run_e4.sh "$@"
run_experiment "E6: Scalability (3-party)"          run_e6.sh "$@"
run_experiment "E7: CPU vs GPU (Q1 no sort)"       run_e7.sh "$@"
run_experiment "E3: SCS + MPC Sort"                run_e3.sh "$@"

echo "════════════════════════════════════════════════════════════"
echo "  All experiments complete."
echo ""
echo "  Logs in: ./data/paper_runs/E{1..7}/"
echo ""
echo "  Next steps:"
echo "    1. Copy data/ from each server to one machine"
echo "    2. python3 scripts/fhe/paper/parse_logs.py --data_dir ./data/paper_runs"
echo "    3. python3 scripts/fhe/paper/generate_figures.py --csv results.csv"
echo "════════════════════════════════════════════════════════════"
