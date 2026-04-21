# HAMMER

User queries may reveal a client's intent with their predicate parameters. Concealing these parameters from the untrusted server during queries over a public database is private information retrieval (PIR), a well-studied problem in cryptography. This work is the first SQL query evaluation system to address a stronger variation of this problem that preserves both predicate confidentiality and the privacy of the database's records -- not revealing them to the client -- the symmetric PIR (SPIR) setting. Prior PIR work used heavyweight fully homomorphic encryption (FHE) schemes while selectively offloading some tasks onto the client to make their performance practical. In our work, the client does not take part in query evaluation, only receiving the final query answer. These settings are well-suited to lightweight clients such as mobile devices. SPIR querying is also useful for settings like anti-money laundering compliance for banks, where regulators issue private queries to learn about how transactions are moving through accounts without divulging information about all their customers to the government.

We present HAMMER, a query execution system that offers SPIR over SQL queries using a combination of local, server-side query evaluation, FHE, and multiparty computation (MPC) to make this process secure and scalable. FHE supports SIMD, which makes it 1-2 OOM faster than MPC on data-parallel operators. We therefore evaluate private filters and aggregates under FHE with operators organized to reduce their circuit depth and we support precise integer arithmetic. For steps with long sequences of conditional logic, such as sorts, we turn to MPC via our novel secure context switch. We convert FHE-encrypted intermediate results into secret shares among the original server and a non-colluding MPC helper node with no client assistance. In addition, HAMMER selects per-query FHE parameters guided by analytical depth bounds, and it supports parallelism on multicore CPUs and GPUs. Our hybrid query evaluation achieves 5.3x-8.4x speedups over the state-of-the-art FHE database on TPC-H workloads. With GPU-accelerated FHE evaluation, the majority of our query workload runs at SF1 in under a minute.

## Supported Queries

TPC-H queries with filter + aggregate patterns:
- **Q1**: Pricing summary (6 aggregates, 4 groups)
- **Q4**: Order priority (1 aggregate, 5 groups)
- **Q5**: Local supplier volume (1 aggregate, 25 groups)
- **Q6**: Revenue forecast (1 aggregate, scalar)
- **Q12**: Shipping modes (2 aggregates, 7 groups)
- **Q19**: Discounted revenue (1 aggregate, scalar, DNF predicates)

## Project Structure

```
src/main/cpp/
  operators/columnar/     # FHE operators (filter, aggregate, project, SCS)
  query_table/columnar/   # FHE column store (encrypted column chunks)
  util/fhe/               # FHE helpers, comparators, 3-party network
  opt/                    # Cost model and parameter optimizer
  parser/                 # JSON query plan parser
  expression/             # Expression tree (comparators, connectors)
  conf/plans/fhe/         # Query plans (JSON) and dictionaries
  conf/sql/tpch/          # TPC-H SQL reference queries
  scripts/HAMMER/         # Experiment scripts (E1-E7)
  test/fhe/               # Test drivers (fhe_tpch_test, unit tests)
  docker/                 # Dockerfiles for reproducible deployment
  profiles/               # Server hardware profiles (auto-generated)
src/main/gpu/             # GPU-accelerated FHE (HEonGPU, optional)
```

## Quick Start (Docker)

### Prerequisites
- Docker 20.10+
- PostgreSQL TPC-H data (loaded automatically from S3, or manually)
- For GPU: NVIDIA GPU with CUDA 12.6+, nvidia-container-toolkit

### Build

```bash
# 1. Build base image (OpenFHE + EMP + libpqxx dependencies)
docker build -t hammer-fhe:base -f src/main/cpp/docker/Dockerfile.base .

# 2. Build HAMMER image
docker build -t hammer:latest -f src/main/cpp/docker/Dockerfile .
```

### Run (Single Server, 3-Party Loopback)

```bash
# All 3 parties on the same machine (for testing/development)
docker run --network=host hammer:latest \
    --party=2 --sf=0.1 \
    -- --filter="FheTpchTest.fhe_tpch_q6" --validation=true &

sleep 3

docker run --network=host hammer:latest \
    --party=3 --sf=0.1 \
    -- --filter="FheTpchTest.fhe_tpch_q6" --validation=true &

sleep 8

docker run --network=host hammer:latest \
    --party=1 --sf=0.1 \
    -- --filter="FheTpchTest.fhe_tpch_q6" --validation=true
```

### Run (Cross-Server, 3 Machines)

```bash
# Machine B (compute server, start first):
docker run --network=host hammer:latest \
    --party=2 --sf=0.1 --charlie_host=<C_IP> \
    -- --filter="FheTpchTest.fhe_tpch_q6"

# Machine C (MPC helper, start second):
docker run --network=host hammer:latest \
    --party=3 --sf=0.1 --alice_host=<A_IP> \
    -- --filter="FheTpchTest.fhe_tpch_q6"

# Machine A (data owner, start last):
docker run --network=host hammer:latest \
    --party=1 --sf=0.1 --bob_host=<B_IP> --charlie_host=<C_IP> \
    -- --filter="FheTpchTest.fhe_tpch_q6"
```

## Building from Source (without Docker)

### Dependencies

| Dependency | Version | Notes |
|-----------|---------|-------|
| Ubuntu | 24.04 | Tested on 24.04 LTS |
| CMake | >= 3.14 | |
| OpenFHE | 1.4.2 | MATHBACKEND=4, shared libs |
| EMP toolkit | latest | emp-tool + emp-ot + emp-sh2pc + emp-zk |
| libpqxx | 7.7.4 | Built with -fPIC |
| PostgreSQL | 16 | For TPC-H data storage |
| Boost | >= 1.74 | date_time, system, program_options |
| OpenSSL | >= 3.0 | |
| gflags | latest | |
| OpenMP | >= 4.5 | For parallel FHE computation |

### Build Steps

```bash
cd src/main/cpp
cmake -DCMAKE_BUILD_TYPE=Release .
make -j$(nproc)
```

For GPU support (requires CUDA 12.6+ and [HEonGPU](https://github.com/Alisah-Ozcan/HEonGPU)):
```bash
cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_GPU=ON .
make -j$(nproc)
```

### Data Setup

HAMMER reads TPC-H data from PostgreSQL. Load the TPC-H dataset:

```bash
# Generate TPC-H data (SF 0.1 = 15,000 lineitem rows)
cd deps/tpch/dbgen
make
./dbgen -s 0.1

# Load into PostgreSQL (schema in conf/sql/tpch/)
createdb tpch_unioned_15000
psql tpch_unioned_15000 < conf/sql/tpch/create_tables.sql
# ... load CSV data ...
```

Or use the S3 data loading built into the experiment scripts:
```bash
source scripts/HAMMER/common.sh
ensure_data_loaded "0.1"
```

## Running Experiments

HAMMER includes scripts for all paper experiments. Each script auto-detects hardware and generates a server profile.

```bash
cd src/main/cpp

# E1: Selective vs all-column encryption
bash scripts/HAMMER/run_e1.sh --sf=0.01

# E2: HAMMER optimizer (Config C) vs baseline (Config A)
bash scripts/HAMMER/run_e2.sh --sf=0.01

# E3: Secure context switch + MPC sort (cross-server)
bash scripts/HAMMER/run_e3_partyC.sh --sf=0.01        # on server C
bash scripts/HAMMER/run_e3_partyBA.sh --charlie_host=<C_IP> --sf=0.01  # on server B

# E4: Comparator radix base ablation
bash scripts/HAMMER/run_e4.sh --sf=0.01

# E7: Full scalability (all queries, multiple SFs)
bash scripts/HAMMER/run_e7.sh --sf="0.01 0.1"

# Dry-run (prints commands without executing)
bash scripts/HAMMER/run_e7.sh --sf=0.01 --dry-run
```

See `scripts/HAMMER/EXPERIMENT_GUIDE.md` for detailed instructions.

## Key Flags

| Flag | Description |
|------|-------------|
| `--fhe_party=N` | Party role: 1=A (data), 2=B (compute), 3=C (helper) |
| `--unioned_db=NAME` | PostgreSQL database name |
| `--server_profile=PATH` | Hardware profile JSON |
| `--fhe_force_baseline` | Disable optimizer, use N=65536, d=15 |
| `--fhe_force_ring_dim=N` | Override ring dimension |
| `--fhe_force_mult_depth=N` | Override multiplicative depth |
| `--fhe_force_threads=N` | Override thread count |
| `--all_column_encrypt` | Full ct-ct path (no plaintext optimization) |
| `--sort_limit=N` | Cap MPC sort input rows |
| `--validation=true` | Verify results against plaintext |

## Architecture

```
Party A (Data Owner)          Party B (Compute)           Party C (Helper)
  - Encrypts data             - Evaluates FHE circuit      - Threshold decryption
  - Sends ciphertexts         - FheFilter (radix cmp)      - MPC sort (EMP)
  - Validates results         - FheAggregate (rotate-sum)
                              - Secure Context Switch
```

**FHE Pipeline per query:**
1. `FheTableScan` — Load encrypted columns from Party A
2. `FheFilter` — Evaluate predicates using radix decomposition comparators
3. `FheAggregate` — Rotate-and-sum with group-by masking
4. (Optional) `SecureContextSwitch` — Threshold decrypt + MPC sort

**Optimizer decisions:**
- Ring dimension N: {32768, 65536} based on multiplicative depth
- Thread count T*: min(P, W) where W = work items, bounded by L3 cache pressure
- Cache batching: chunks sized to fit working set in L3

## License

This project is released for research purposes. See LICENSE for details.

## Citation

Paper under review. Citation details will be added upon publication.
