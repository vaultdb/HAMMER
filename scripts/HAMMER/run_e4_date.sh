#!/bin/bash
# run_e4_date.sh — E4: Date Predicate Base Ablation (5 date-pred queries only)
# Bases 2/4/8 use auto params; base 16 uses forced ring_dim/mult_depth.
# Excludes Q19 (string predicates, not date) and base 64 (infeasible).
# ════════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

parse_common_args "$@"
SF_LIST="${SF_LIST:-0.01}"
common_init
ensure_data_loaded "$SF_LIST"

OUT_DIR="./data/paper_runs/E4/${SERVER_NAME}"
mkdir -p "$OUT_DIR"

BASES=(2 4 8 16)
QUERIES=(q1 q4 q5 q6 q12)
CWD="$(pwd)"

# Base 16 forced mult_depth per query (actual d_lb + 2 safety margin)
declare -A B16_DEPTH=(
    [q1]=21
    [q4]=22
    [q5]=23
    [q6]=24
    [q12]=23
)

echo "════════════════════════════════════════════════════════════"
echo "  E4: Date Predicate Base Ablation"
echo "  Queries: ${QUERIES[*]}"
echo "  Bases: ${BASES[*]}, SF: ${SF_LIST}"
echo "════════════════════════════════════════════════════════════"

for SF in $SF_LIST; do
  for Q in "${QUERIES[@]}"; do
    GF="${QUERY_FILTER[$Q]}"
    for BASE in "${BASES[@]}"; do
      PLAN_PATH="${CWD}/conf/plans/fhe/base_ablation/${Q}_base${BASE}.json"

      if [[ ! -f "$PLAN_PATH" ]]; then
          echo "[E4] ${Q} $(sf_label $SF) base=${BASE} — SKIP (no plan file)"
          continue
      fi

      PREFIX="${OUT_DIR}/e4_base${BASE}_${Q}_$(sf_label $SF)"
      if already_passed "$PREFIX"; then
          echo "[E4] ${Q} $(sf_label $SF) base=${BASE} — SKIP (already passed)"
      else
          if [[ "$BASE" -eq 16 ]]; then
              FORCED_M="${B16_DEPTH[$Q]}"
              echo "[E4] ${Q} $(sf_label $SF) base=${BASE} T=${P} (forced N=65536 m=${FORCED_M})"
              run_3party "$SF" "$GF" "$P" "$PREFIX" \
                  "--fhe_plan_path_override=${PLAN_PATH} --fhe_force_threads=${P} --fhe_force_ring_dim=65536 --fhe_force_mult_depth=${FORCED_M}"
          else
              echo "[E4] ${Q} $(sf_label $SF) base=${BASE} T=${P}"
              run_3party "$SF" "$GF" "$P" "$PREFIX" \
                  "--fhe_plan_path_override=${PLAN_PATH} --fhe_force_threads=${P}"
          fi
      fi
    done
    echo ""
  done
done

parse_results "$OUT_DIR"

# ── Base 64 infeasibility analysis ──────────────────────────────
cat <<'EOF'

════════════════════════════════════════════════════════════
  Base 64 Infeasibility Analysis
════════════════════════════════════════════════════════════
  Phase A (ternary comparator): base-1 = 63 levels
  Per-predicate depth (63 + 1 carry + 2 lexicographic) = 66
  Required mult_depth with aggregate ≈ 70

  N = 131072 (next power-of-2):
    log2(Q) = 70 × 60 = 4200 bits > 3600-bit security bound → INFEASIBLE

  N = 262144 (would satisfy depth):
    CT size  = 2 × 71 × 262144 × 8 ≈ 284 MB per ciphertext
    Rot keys ≈ 20 indices × 284 MB  ≈ 5.7 GB
    → Impractical memory and runtime

  Conclusion: base 64 is infeasible for BFV with current security parameters.
════════════════════════════════════════════════════════════
EOF

echo "  E4 (date predicates) done."
