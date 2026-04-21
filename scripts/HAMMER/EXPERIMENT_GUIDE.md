# HAMMER Experiment Running Guide

## Servers

| Name | Hostname | CPU | P | H | L3 | Role |
|------|----------|-----|---|---|-----|------|
| SPR | sn4622124096 (IIT) | Xeon w5-3435X (Sapphire Rapids) | 16 | 32 | 45MB | Party B (compute) |
| IVB | codd08 | Xeon E5-2420 v2 (Ivy Bridge) | 6 | 12 | 15MB | Party C (MPC helper) |

## Scale Factor Mapping

| DB name | SF value | Flag |
|---------|----------|------|
| tpch_unioned_150 | 0.001 | `--sf=0.001` |
| tpch_unioned_1500 | 0.01 | `--sf=0.01` |
| tpch_unioned_15000 | 0.1 | `--sf=0.1` |

## Prerequisites

```bash
# Build on each server
cd src/main/cpp
make -j4 fhe_tpch_test

# Verify binary exists
ls -la bin/fhe_tpch_test
```

---

## Single-Server Experiments (IIT only)

### E1 + E2 + E4 together

```bash
# On IIT:
nohup bash scripts/HAMMER/run_SPR_single.sh --sf=0.01 \
  > data/paper_runs/spr_single.log 2>&1 &
```

### E1: Selective vs All-Column Encryption
- Queries: q1_one_sum, q6, q12
- Both configs use `--fhe_force_baseline` (ring_dim=65536, mult_depth=15, T=P)
- Shows ct-pt vs ct-ct overhead is <3%

```bash
bash scripts/HAMMER/run_e1.sh --sf=0.01
```

### E2: HAMMER Config C vs Config A
- Queries: q1_one_sum, q6, q12
- Config C: adaptive ring_dim/mult_depth, T*=auto (HAMMER full)
- Config A: forced baseline (ring_dim=65536, mult_depth=15, T=P)

```bash
bash scripts/HAMMER/run_e2.sh --sf=0.01
```

### E4: Comparator Base Ablation
- Query: q1, bases {2, 4, 16, 64}
- Uses `--fhe_plan_path_override` for each base

```bash
bash scripts/HAMMER/run_e4.sh --sf=0.01
```

---

## Cross-Server Experiments (IIT + codd)

E3 and E5 run Party B + A on IIT (SPR) and Party C on codd (IVB).
**Always start Party C (codd) FIRST, then Party B+A (IIT).**

### E3: SCS + MPC Sort vs Engorgio HomSort
- Test: sort_lineitem (FheTableScan -> SCS -> LogicalSort)
- SF=0.01 (tpch_unioned_1500), sort_limit sweep: {64, 256, 1024, 4096, 8192}
- `--sort_limit` adds SQL LIMIT to bound input size at scan

```bash
# Step 1: On codd (Party C) — start FIRST
nohup bash scripts/HAMMER/run_e3_partyC.sh --sf=0.01 \
  > data/paper_runs/E3/codd_e3_partyC.log 2>&1 &

# Step 2: On IIT (Party B + A) — start AFTER codd is ready
nohup bash scripts/HAMMER/run_e3_partyBA.sh --charlie_host=codd08 --sf=0.01 \
  > data/paper_runs/E3/iit_e3_partyBA.log 2>&1 &
```

Reports per-run: scs_ms, sort_ms, total_ms (extracted from Party B log).

### E5: SMT Policy Portability
- Queries: q1, q5
- Thread sweep: {P/2, P, 3P/2, 2P, H} deduplicated
- Old (baseline N=65536,m=15) vs New (adaptive) vs Auto

```bash
# Step 1: On codd (Party C) — start FIRST
nohup bash scripts/HAMMER/run_e5_partyC.sh --sf=0.1 \
  > data/paper_runs/E5/codd_e5_partyC.log 2>&1 &

# Step 2: On IIT (Party B + A)
nohup bash scripts/HAMMER/run_e5_partyBA.sh --charlie_host=codd08 --sf=0.1 \
  > data/paper_runs/E5/iit_e5_partyBA.log 2>&1 &
```

---

## Monitoring

```bash
# Check if running
ps aux | grep fhe_tpch_test | grep -v grep

# Tail the log
tail -30 data/paper_runs/spr_single.log

# Check results CSV
cat data/paper_runs/E1/<hostname>/results.csv

# Kill everything
pkill -9 -f fhe_tpch_test
```

## Results Location

All logs and results are stored under `data/paper_runs/`:
```
data/paper_runs/
  E1/<hostname>/          # e1_selective_q1_one_sum_sf_0.1_party_{a,b,c}.log
  E2/<hostname>/          # config_c_q1_one_sum_sf_0.1_party_{a,b,c}.log
  E3/<hostname>/          # e3_sort_64_sf_0.01_party_{b,c}.log (+ party_a on IIT)
  E4/<hostname>/          # e4_base4_q1_sf_0.01_party_{a,b,c}.log
  E5/<hostname>/          # e5_new_q1_sf_0.1_T16_party_{a,b,c}.log
```

Each experiment directory also gets a `results.csv` with columns:
`experiment,query,config,ring_dim,threads,runtime_sec,status`

## Experiment Summary

| Exp | Server | What | Priority |
|-----|--------|------|----------|
| E1 | IIT single | Selective vs all-column encrypt | 1 |
| E2 | IIT single | HAMMER Config C vs A (+ Engorgio separately) | 2 |
| E4 | IIT single | Comparator base ablation (2/4/16/64) | 3 |
| E3 | IIT+codd | SCS+MPC sort vs HomSort | 4 |
| E5 | IIT+codd | SMT policy portability (thread sweep) | 5 |
| E6 | — | GPU vs CPU (stub) | 6 |
| E7 | — | Scalability (all queries, multi-SF) | 7 |

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `--sf=X` | Scale factor (0.001/0.01/0.1) |
| `--dry-run` | Print commands without running |
| `--charlie_host=HOST` | Party C hostname (cross-server only) |
| `--fhe_force_baseline` | Force ring_dim=65536, mult_depth=15 |
| `--fhe_force_threads=N` | Override SMT thread selection |
| `--sort_limit=N` | SQL LIMIT on scan + cap SCS rows |
| `--all_column_encrypt` | ct-ct mode (E1 allcol) |
| `--fhe_plan_path_override=PATH` | Override plan JSON (E4) |
