#!/usr/bin/env python3
"""
Full E5 log parser — extracts all metrics from Party B logs for both servers.
Produces:
  1. e5_full_results.csv — one row per log file
  2. Table 1: FheFilter latency by thread count with policy validation
  3. Table 2: FheAggregate latency by thread count with policy validation
  4. Table 3: Per-operator policy validation for auto runs
  5. Summary table with key numbers
"""

import os
import re
import csv
import sys
from collections import defaultdict

E5_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'paper_runs', 'E5')

def parse_log(filepath):
    """Parse a single Party B log file and return a dict of metrics."""
    fname = os.path.basename(filepath)
    server_dir = os.path.basename(os.path.dirname(filepath))

    # Parse filename for config/query/T
    # Patterns:
    #   e5_new_q1_sf_0.1_T12_party_b.log
    #   e5_old_q1_sf_0.1_T12_party_b.log
    #   e5_auto_q1_sf_0.1_party_b.log
    m = re.match(r'e5_(new|old|auto)_(q\d+)_sf_[\d.]+(?:_T(\d+))?_party_b\.log', fname)
    if not m:
        return None

    config = m.group(1)
    query = m.group(2)
    T_filename = int(m.group(3)) if m.group(3) else None

    rec = {
        'file': fname,
        'server_dir': server_dir,
        'config': config,
        'query': query,
        'T_filename': T_filename,
        'server_name': None,
        'P': None, 'H': None, 'L3_mb': None,
        'ring_dim': None, 'mult_depth': None, 'L_eff': None,
        'rho_filter': None, 'rho_agg': None,
        'ws_filter_mb': None, 'ws_agg_mb': None,
        'ct_mb': None,
        'T_filter_policy': None, 'T_filter_policy_reason': None,
        'T_agg_policy': None, 'T_agg_policy_reason': None,
        'T_filter_override': None, 'T_agg_override': None,
        'filter_ms': None, 'agg_ms': None,
        'scs_ms': None,
        'total_runtime_sec': None,
        'omp_threads': None,
        'fhe_force_baseline': False,
        'fhe_force_threads': None,
        'passed': False,
        # Perf counters
        'filter_llc_miss': None, 'filter_llc_ref': None, 'filter_llc_miss_rate': None,
        'filter_ipc': None, 'filter_stall_mem_frac': None,
        'agg_llc_miss': None, 'agg_llc_ref': None, 'agg_llc_miss_rate': None,
        'agg_ipc': None, 'agg_stall_mem_frac': None,
        # Chunk info
        'filter_chunks': None, 'filter_work_items': None,
        'filter_chunk_avg_ms_ch0': None,
    }

    with open(filepath, 'r', errors='replace') as f:
        text = f.read()

    # Server profile
    m2 = re.search(r'\[ServerProfile\] P=(\d+) H=(\d+) L3=(\d+)MB', text)
    if m2:
        rec['P'] = int(m2.group(1))
        rec['H'] = int(m2.group(2))
        rec['L3_mb'] = int(m2.group(3))

    # Server name from profile path
    m2 = re.search(r'\[ServerProfile\] Loaded: .*/server_profile_(\w+)\.json', text)
    if m2:
        rec['server_name'] = m2.group(1)

    # QueryPlan FHE params
    m2 = re.search(r'\[QueryPlan\] FHE:\s+ring_dim=(\d+)\s+mult_depth=(\d+)\s+L_eff=(\d+)', text)
    if m2:
        rec['ring_dim'] = int(m2.group(1))
        rec['mult_depth'] = int(m2.group(2))
        rec['L_eff'] = int(m2.group(3))

    # rho values
    m2 = re.search(r'\[QueryPlan\] rho:\s+filter=([\d.]+)\s+\((\w+)\)\s+agg=([\d.]+)\s+\((\w+)\)', text)
    if m2:
        rec['rho_filter'] = float(m2.group(1))
        rec['rho_agg'] = float(m2.group(3))

    # CT and working set
    m2 = re.search(r'\[QueryPlan\] CT:\s+ct=([\d.]+)MB\s+ws_f=([\d.]+)MB\s+ws_a=([\d.]+)MB', text)
    if m2:
        rec['ct_mb'] = float(m2.group(1))
        rec['ws_filter_mb'] = float(m2.group(2))
        rec['ws_agg_mb'] = float(m2.group(3))

    # Filter SMT policy
    m2 = re.search(r'\[QueryPlan/Filter\] SMT: rho=([\d.]+) -> T\*=(\d+) \(([^)]+)\)', text)
    if m2:
        rec['T_filter_policy'] = int(m2.group(2))
        rec['T_filter_policy_reason'] = m2.group(3)

    # Filter override
    m2 = re.search(r'\[QueryPlan/Filter\] OVERRIDE: T\*=\d+ -> T=(\d+)', text)
    if m2:
        rec['T_filter_override'] = int(m2.group(1))

    # Agg SMT policy
    m2 = re.search(r'\[QueryPlan/Agg\] SMT: rho=([\d.]+) -> T\*=(\d+) \(([^)]+)\)', text)
    if m2:
        rec['T_agg_policy'] = int(m2.group(2))
        rec['T_agg_policy_reason'] = m2.group(3)

    # Agg override
    m2 = re.search(r'\[QueryPlan/Agg\] OVERRIDE: T\*=\d+ -> T=(\d+)', text)
    if m2:
        rec['T_agg_override'] = int(m2.group(1))

    # OMP threads
    m2 = re.search(r'\[OpenMP\] max_threads=(\d+)', text)
    if m2:
        rec['omp_threads'] = int(m2.group(1))

    # GFlags
    if '--fhe_force_baseline=true' in text:
        rec['fhe_force_baseline'] = True
    m2 = re.search(r'--fhe_force_threads=(\d+)', text)
    if m2:
        rec['fhe_force_threads'] = int(m2.group(1))

    # Filter timing
    m2 = re.search(r'\[Timing\] Operator #1 \(FheFilter\): ([\d.]+) ms', text)
    if m2:
        rec['filter_ms'] = float(m2.group(1))

    # Aggregate timing
    m2 = re.search(r'\[Timing\] Operator #2 \(FheAggregate\): ([\d.]+) ms', text)
    if m2:
        rec['agg_ms'] = float(m2.group(1))

    # SCS timing
    m2 = re.search(r'Operator #3 SecureContextSwitch ran for ([\d.]+) ms', text)
    if m2:
        rec['scs_ms'] = float(m2.group(1))

    # Total runtime
    m2 = re.search(r'\[FheTpchTest\] Runtime(?:\s*\(FHE-only\))?: ([\d.]+) sec', text)
    if m2:
        rec['total_runtime_sec'] = float(m2.group(1))

    # Pass/fail
    if '[  PASSED  ]' in text:
        rec['passed'] = True

    # Filter perf stats
    m2 = re.search(r'\[PerfStats FheFilter\] LLC_miss=(\d+) LLC_ref=(\d+) LLC_miss_rate=([\d.]+) instructions=(\d+) cycles=(\d+) IPC=([\d.]+) stall_mem=\d+ stall_mem_frac=([\d.]+)', text)
    if m2:
        rec['filter_llc_miss'] = int(m2.group(1))
        rec['filter_llc_ref'] = int(m2.group(2))
        rec['filter_llc_miss_rate'] = float(m2.group(3))
        rec['filter_ipc'] = float(m2.group(6))
        rec['filter_stall_mem_frac'] = float(m2.group(7))

    # Agg perf stats
    m2 = re.search(r'\[PerfStats FheAggregate\] LLC_miss=(\d+) LLC_ref=(\d+) LLC_miss_rate=([\d.]+) instructions=(\d+) cycles=(\d+) IPC=([\d.]+) stall_mem=\d+ stall_mem_frac=([\d.]+)', text)
    if m2:
        rec['agg_llc_miss'] = int(m2.group(1))
        rec['agg_llc_ref'] = int(m2.group(2))
        rec['agg_llc_miss_rate'] = float(m2.group(3))
        rec['agg_ipc'] = float(m2.group(6))
        rec['agg_stall_mem_frac'] = float(m2.group(7))

    # Filter chunk info
    m2 = re.search(r'\[QueryPlan/Filter\] query: chunks=(\d+) work_items=(\d+)', text)
    if m2:
        rec['filter_chunks'] = int(m2.group(1))
        rec['filter_work_items'] = int(m2.group(2))

    m2 = re.search(r'\[FheFilter\]\[Perf\] ch=0 chunks=\d+ chunk_avg_ms=([\d.]+)', text)
    if m2:
        rec['filter_chunk_avg_ms_ch0'] = float(m2.group(1))

    # Determine effective T
    if rec['fhe_force_threads'] and rec['fhe_force_threads'] > 0:
        rec['T_effective'] = rec['fhe_force_threads']
    elif rec['omp_threads']:
        rec['T_effective'] = rec['omp_threads']
    elif rec['T_filename']:
        rec['T_effective'] = rec['T_filename']
    else:
        rec['T_effective'] = None

    return rec


def collect_all_logs():
    """Collect all Party B logs from all server directories (auto-discovered)."""
    records = []
    for server_dir in sorted(os.listdir(E5_DIR)):
        dirpath = os.path.join(E5_DIR, server_dir)
        if not os.path.isdir(dirpath):
            continue
        # Only include dirs that contain e5 party_b logs
        has_logs = any(f.endswith('_party_b.log') and f.startswith('e5_')
                       for f in os.listdir(dirpath))
        if not has_logs:
            continue
        for fname in sorted(os.listdir(dirpath)):
            if fname.endswith('_party_b.log') and fname.startswith('e5_'):
                rec = parse_log(os.path.join(dirpath, fname))
                if rec:
                    records.append(rec)
    return records


def write_csv(records, outpath):
    """Write full CSV."""
    cols = [
        'server_dir', 'server_name', 'query', 'config', 'T_effective',
        'filter_ms', 'agg_ms', 'total_runtime_sec',
        'rho_filter', 'rho_agg',
        'ring_dim', 'mult_depth', 'L_eff', 'ct_mb', 'ws_filter_mb', 'ws_agg_mb',
        'P', 'H', 'L3_mb',
        'T_filter_policy', 'T_filter_policy_reason', 'T_filter_override',
        'T_agg_policy', 'T_agg_policy_reason', 'T_agg_override',
        'fhe_force_baseline', 'fhe_force_threads', 'omp_threads',
        'filter_chunks', 'filter_work_items', 'filter_chunk_avg_ms_ch0',
        'filter_llc_miss_rate', 'filter_ipc', 'filter_stall_mem_frac',
        'agg_llc_miss_rate', 'agg_ipc', 'agg_stall_mem_frac',
        'passed', 'file',
    ]
    with open(outpath, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction='ignore')
        w.writeheader()
        for r in records:
            w.writerow(r)
    print(f"Wrote {outpath} ({len(records)} rows)")


def get_servers(records):
    """Return sorted unique server_dir values from records."""
    seen = []
    for r in records:
        if r['server_dir'] not in seen:
            seen.append(r['server_dir'])
    return seen


def fmt_ms(v):
    """Format ms as seconds with 1 decimal."""
    if v is None:
        return '—'
    return f"{v/1000:.1f}s"


def fmt_ms_raw(v):
    """Format ms as integer."""
    if v is None:
        return '—'
    return f"{v:.0f}"


def print_table1_filter(records):
    """Table 1: FheFilter latency by thread count, with policy validation."""
    print("\n" + "="*120)
    print("TABLE 1: FheFilter Latency by Thread Count")
    print("="*120)

    # Group by (server_dir, query, config)
    groups = defaultdict(list)
    for r in records:
        groups[(r['server_dir'], r['query'], r['config'])].append(r)

    for server in get_servers(records):
        print(f"\n--- Server: {server} ---")
        for query in ['q1', 'q5', 'q12']:
            print(f"\n  Query: {query}")
            for config in ['new', 'old']:
                key = (server, query, config)
                if key not in groups:
                    continue
                runs = sorted(groups[key], key=lambda r: r['T_effective'] or 0)
                if not runs:
                    continue

                # Find optimal T
                valid = [r for r in runs if r['filter_ms'] is not None]
                if not valid:
                    continue
                best = min(valid, key=lambda r: r['filter_ms'])

                rho = runs[0]['rho_filter']
                P = runs[0]['P']
                H = runs[0]['H']
                L3 = runs[0]['L3_mb']

                # Expected policy
                if rho is not None and rho < 1.05:
                    expected_T = H
                    expected_reason = "LLC-fit"
                else:
                    expected_T = P
                    expected_reason = "DRAM-bound"

                policy_match = "YES" if best['T_effective'] == expected_T else "NO"

                print(f"    Config={config}  rho={rho}  ring_dim={runs[0]['ring_dim']}  "
                      f"P={P} H={H} L3={L3}MB  expected_T*={expected_T} ({expected_reason})")
                print(f"    {'T':>4}  {'filter_ms':>12}  {'chunk_avg':>12}  {'LLC_miss%':>10}  {'IPC':>6}  {'optimal':>8}")
                print(f"    {'─'*4}  {'─'*12}  {'─'*12}  {'─'*10}  {'─'*6}  {'─'*8}")
                for r in runs:
                    T = r['T_effective']
                    fms = fmt_ms_raw(r['filter_ms'])
                    cavg = f"{r['filter_chunk_avg_ms_ch0']:.0f}" if r['filter_chunk_avg_ms_ch0'] else '—'
                    llc = f"{r['filter_llc_miss_rate']:.2f}" if r['filter_llc_miss_rate'] is not None else '—'
                    ipc = f"{r['filter_ipc']:.2f}" if r['filter_ipc'] is not None else '—'
                    star = " ★" if r is best else ""
                    print(f"    {T:>4}  {fms:>12}  {cavg:>12}  {llc:>10}  {ipc:>6}{star}")

                print(f"    → Optimal T={best['T_effective']}, Policy T*={expected_T}: {policy_match}")

            # Auto run
            auto_key = (server, query, 'auto')
            if auto_key in groups:
                auto_runs = groups[auto_key]
                if auto_runs:
                    ar = auto_runs[0]
                    print(f"    Auto: T_filter_policy={ar['T_filter_policy']} "
                          f"({ar['T_filter_policy_reason']})  "
                          f"filter_ms={fmt_ms_raw(ar['filter_ms'])}  "
                          f"T_effective={ar['T_effective']}")


def print_table2_agg(records):
    """Table 2: FheAggregate latency by thread count, with policy validation."""
    print("\n" + "="*120)
    print("TABLE 2: FheAggregate Latency by Thread Count")
    print("="*120)

    groups = defaultdict(list)
    for r in records:
        groups[(r['server_dir'], r['query'], r['config'])].append(r)

    for server in get_servers(records):
        print(f"\n--- Server: {server} ---")
        for query in ['q1', 'q5', 'q12']:
            print(f"\n  Query: {query}")
            for config in ['new', 'old']:
                key = (server, query, config)
                if key not in groups:
                    continue
                runs = sorted(groups[key], key=lambda r: r['T_effective'] or 0)
                valid = [r for r in runs if r['agg_ms'] is not None]
                if not valid:
                    continue
                best = min(valid, key=lambda r: r['agg_ms'])

                rho_agg = runs[0]['rho_agg']
                H = runs[0]['H']
                P = runs[0]['P']

                # New policy: agg always uses H
                # Old policy would have been: rho < 1.05 → H, else → P
                old_expected = H if (rho_agg is not None and rho_agg < 1.05) else P

                # Flag: rho >= 1.05 but optimal is H (proves H is better for agg even when spilling)
                flag = ""
                if rho_agg is not None and rho_agg >= 1.05 and best['T_effective'] == H:
                    flag = " ⚠ DRAM-bound by rho but optimal=H!"

                print(f"    Config={config}  rho_agg={rho_agg}  "
                      f"P={P} H={H}  old_policy_T*={old_expected}{flag}")
                print(f"    {'T':>4}  {'agg_ms':>12}  {'LLC_miss%':>10}  {'IPC':>6}  {'optimal':>8}")
                print(f"    {'─'*4}  {'─'*12}  {'─'*10}  {'─'*6}  {'─'*8}")
                for r in runs:
                    T = r['T_effective']
                    ams = fmt_ms_raw(r['agg_ms'])
                    llc = f"{r['agg_llc_miss_rate']:.2f}" if r['agg_llc_miss_rate'] is not None else '—'
                    ipc = f"{r['agg_ipc']:.2f}" if r['agg_ipc'] is not None else '—'
                    star = " ★" if r is best else ""
                    print(f"    {T:>4}  {ams:>12}  {llc:>10}  {ipc:>6}{star}")

                print(f"    → Optimal T={best['T_effective']}, always-H policy T*={H}: "
                      f"{'MATCH' if best['T_effective'] == H else 'MISMATCH'}")

            # Auto run
            auto_key = (server, query, 'auto')
            if auto_key in groups:
                ar = groups[auto_key][0]
                print(f"    Auto: T_agg_policy={ar['T_agg_policy']} "
                      f"({ar['T_agg_policy_reason']})  "
                      f"agg_ms={fmt_ms_raw(ar['agg_ms'])}  "
                      f"T_effective={ar['T_effective']}")


def print_table3_auto_validation(records):
    """Table 3: Per-operator policy validation for auto runs."""
    print("\n" + "="*120)
    print("TABLE 3: Auto Run Policy Validation")
    print("="*120)

    groups = defaultdict(list)
    for r in records:
        groups[(r['server_dir'], r['query'], r['config'])].append(r)

    print(f"\n{'server':<16} {'query':<6} {'rho_f':>6} {'rho_a':>6} "
          f"{'T_f_pol':>8} {'T_a_pol':>8} {'T_eff':>6} "
          f"{'filter_ms':>12} {'agg_ms':>12} {'total_s':>10} "
          f"{'f_reason':<40} {'a_reason':<30}")
    print("─" * 170)

    for server in get_servers(records):
        for query in ['q1', 'q5', 'q12']:
            key = (server, query, 'auto')
            if key not in groups:
                continue
            ar = groups[key][0]

            # Check if filter policy is overridden
            f_override = ""
            if ar['T_filter_override'] is not None and ar['T_filter_override'] != ar['T_filter_policy']:
                f_override = f" (OVERRIDE→{ar['T_filter_override']})"

            # Find optimal from sweep for comparison
            new_key = (server, query, 'new')
            new_runs = groups.get(new_key, [])
            best_filter_T = None
            best_agg_T = None
            if new_runs:
                valid_f = [r for r in new_runs if r['filter_ms'] is not None]
                valid_a = [r for r in new_runs if r['agg_ms'] is not None]
                if valid_f:
                    best_filter_T = min(valid_f, key=lambda r: r['filter_ms'])['T_effective']
                if valid_a:
                    best_agg_T = min(valid_a, key=lambda r: r['agg_ms'])['T_effective']

            f_match = "✓" if ar['T_filter_policy'] == best_filter_T else f"✗(opt={best_filter_T})"
            a_match = "✓" if ar['T_agg_policy'] == ar['H'] else f"✗(!=H={ar['H']})"

            print(f"{server:<16} {query:<6} {ar['rho_filter'] or 0:>6.2f} {ar['rho_agg'] or 0:>6.2f} "
                  f"{ar['T_filter_policy'] or 0:>8} {ar['T_agg_policy'] or 0:>8} {ar['T_effective'] or 0:>6} "
                  f"{fmt_ms_raw(ar['filter_ms']):>12} {fmt_ms_raw(ar['agg_ms']):>12} {ar['total_runtime_sec'] or 0:>10.1f} "
                  f"{(ar['T_filter_policy_reason'] or ''):<40} {(ar['T_agg_policy_reason'] or ''):<30} "
                  f"f:{f_match} a:{a_match}")


def print_summary(records):
    """Summary table with key numbers."""
    print("\n" + "="*120)
    print("TABLE 4: Key Numbers Summary")
    print("="*120)

    groups = defaultdict(list)
    for r in records:
        groups[(r['server_dir'], r['query'], r['config'])].append(r)

    print(f"\n{'server':<16} {'query':<6} "
          f"{'auto_total':>12} {'auto_filter':>12} {'auto_agg':>12} "
          f"{'best_old_total':>14} {'speedup':>8} "
          f"{'filt_opt_T':>10} {'filt_pol_T':>10} {'f_match':>8} "
          f"{'agg_opt_T':>10} {'agg=H?':>8} "
          f"{'rho_f':>6} {'rho_a':>6} {'ring_dim':>10}")
    print("─" * 180)

    for server in get_servers(records):
        for query in ['q1', 'q5', 'q12']:
            # Auto run
            auto_key = (server, query, 'auto')
            if auto_key not in groups:
                continue
            ar = groups[auto_key][0]

            # Find best old run at same T as auto (or closest)
            old_key = (server, query, 'old')
            old_runs = groups.get(old_key, [])
            auto_T = ar['T_effective']

            # Find old run at auto's T
            old_at_T = [r for r in old_runs if r['T_effective'] == auto_T]
            if old_at_T:
                old_total = old_at_T[0]['total_runtime_sec']
            else:
                # Use best old run
                valid_old = [r for r in old_runs if r['total_runtime_sec'] is not None]
                if valid_old:
                    best_old = min(valid_old, key=lambda r: r['total_runtime_sec'])
                    old_total = best_old['total_runtime_sec']
                else:
                    old_total = None

            speedup = f"{old_total / ar['total_runtime_sec']:.2f}x" if old_total and ar['total_runtime_sec'] else '—'

            # Optimal T from new sweep
            new_key = (server, query, 'new')
            new_runs = groups.get(new_key, [])
            best_filter_T = '—'
            best_agg_T = '—'
            if new_runs:
                valid_f = [r for r in new_runs if r['filter_ms'] is not None]
                valid_a = [r for r in new_runs if r['agg_ms'] is not None]
                if valid_f:
                    best_filter_T = min(valid_f, key=lambda r: r['filter_ms'])['T_effective']
                if valid_a:
                    best_agg_T = min(valid_a, key=lambda r: r['agg_ms'])['T_effective']

            f_pol = ar['T_filter_policy']
            f_match = "YES" if f_pol == best_filter_T else "NO"
            a_eq_H = "YES" if best_agg_T == ar['H'] else "NO"

            auto_total = f"{ar['total_runtime_sec']:.1f}" if ar['total_runtime_sec'] else '—'
            old_total_s = f"{old_total:.1f}" if old_total else '—'

            print(f"{server:<16} {query:<6} "
                  f"{auto_total:>12} {fmt_ms_raw(ar['filter_ms']):>12} {fmt_ms_raw(ar['agg_ms']):>12} "
                  f"{old_total_s:>14} {speedup:>8} "
                  f"{best_filter_T:>10} {f_pol:>10} {f_match:>8} "
                  f"{best_agg_T:>10} {a_eq_H:>8} "
                  f"{ar['rho_filter'] or 0:>6.2f} {ar['rho_agg'] or 0:>6.2f} {ar['ring_dim'] or 0:>10}")


def print_portability(records):
    """Cross-server portability comparison."""
    print("\n" + "="*120)
    print("TABLE 5: Cross-Server Portability — Does ρ adapt?")
    print("="*120)

    groups = defaultdict(list)
    for r in records:
        groups[(r['server_dir'], r['query'], r['config'])].append(r)

    servers = get_servers(records)
    # Build column headers from auto records
    server_headers = {}
    for s in servers:
        # Find any auto record to get P/H/L3
        for q in ['q1', 'q5', 'q12']:
            autos = groups.get((s, q, 'auto'), [])
            if autos:
                r = autos[0]
                server_headers[s] = f"{s} (P={r['P']},H={r['H']},L3={r['L3_mb']}MB)"
                break
        if s not in server_headers:
            server_headers[s] = s

    col_width = 35
    header = f"{'query':<6} {'metric':<20}" + "".join(f"{server_headers[s]:>{col_width}}" for s in servers)
    print(f"\n{header}")
    print("─" * (26 + col_width * len(servers)))

    for query in ['q1', 'q5', 'q12']:
        autos = {}
        for s in servers:
            a = groups.get((s, query, 'auto'), [None])[0]
            autos[s] = a

        if not any(autos.values()):
            continue

        metrics = ['rho_filter', 'rho_agg', 'ring_dim', 'T_filter_policy', 'T_agg_policy',
                   'filter_ms', 'agg_ms', 'total_sec']

        for label in metrics:
            vals = []
            for s in servers:
                ar = autos[s]
                if ar is None:
                    vals.append('—')
                elif label == 'rho_filter':
                    vals.append(f"{ar['rho_filter']:.2f}" if ar['rho_filter'] else '—')
                elif label == 'rho_agg':
                    vals.append(f"{ar['rho_agg']:.2f}" if ar['rho_agg'] else '—')
                elif label == 'ring_dim':
                    vals.append(f"{ar['ring_dim']}")
                elif label == 'T_filter_policy':
                    vals.append(f"{ar['T_filter_policy']} ({ar['T_filter_policy_reason']})")
                elif label == 'T_agg_policy':
                    vals.append(f"{ar['T_agg_policy']} ({ar['T_agg_policy_reason']})")
                elif label == 'filter_ms':
                    vals.append(fmt_ms_raw(ar['filter_ms']))
                elif label == 'agg_ms':
                    vals.append(fmt_ms_raw(ar['agg_ms']))
                elif label == 'total_sec':
                    vals.append(f"{ar['total_runtime_sec']:.1f}" if ar['total_runtime_sec'] else '—')

            q_label = query if label == 'rho_filter' else ''
            row = f"{q_label:>6} {label:<20}" + "".join(f"{v:>{col_width}}" for v in vals)
            print(row)
        print()


def print_full_sweep_table(records):
    """Print complete sweep data for all configs."""
    print("\n" + "="*140)
    print("FULL SWEEP DATA (every measurement)")
    print("="*140)

    for server in get_servers(records):
        server_recs = [r for r in records if r['server_dir'] == server]
        if not server_recs:
            continue
        print(f"\n--- {server} (P={server_recs[0]['P']} H={server_recs[0]['H']} L3={server_recs[0]['L3_mb']}MB) ---")
        print(f"{'query':<6} {'config':<6} {'T':>4} "
              f"{'filter_ms':>12} {'agg_ms':>12} {'total_s':>10} "
              f"{'rho_f':>6} {'rho_a':>6} {'ring_dim':>8} {'m_depth':>7} {'L_eff':>5} "
              f"{'ws_f_mb':>7} {'ct_mb':>6} {'chunks':>6} "
              f"{'f_llc%':>7} {'f_ipc':>6} {'a_llc%':>7} {'a_ipc':>6} {'pass':>5}")
        print("─" * 140)

        for query in ['q1', 'q5', 'q12']:
            for config in ['new', 'old', 'auto']:
                runs = sorted(
                    [r for r in server_recs if r['query'] == query and r['config'] == config],
                    key=lambda r: r['T_effective'] or 0
                )
                for r in runs:
                    T = r['T_effective'] or 0
                    fms = f"{r['filter_ms']:.0f}" if r['filter_ms'] else '—'
                    ams = f"{r['agg_ms']:.0f}" if r['agg_ms'] else '—'
                    ts = f"{r['total_runtime_sec']:.1f}" if r['total_runtime_sec'] else '—'
                    rf = f"{r['rho_filter']:.2f}" if r['rho_filter'] else '—'
                    ra = f"{r['rho_agg']:.2f}" if r['rho_agg'] else '—'
                    rd = r['ring_dim'] or 0
                    md = r['mult_depth'] or 0
                    le = r['L_eff'] or 0
                    ws = f"{r['ws_filter_mb']:.1f}" if r['ws_filter_mb'] else '—'
                    ct = f"{r['ct_mb']:.1f}" if r['ct_mb'] else '—'
                    ch = r['filter_chunks'] or '—'
                    fllc = f"{r['filter_llc_miss_rate']:.2f}" if r['filter_llc_miss_rate'] is not None else '—'
                    fipc = f"{r['filter_ipc']:.2f}" if r['filter_ipc'] is not None else '—'
                    allc = f"{r['agg_llc_miss_rate']:.2f}" if r['agg_llc_miss_rate'] is not None else '—'
                    aipc = f"{r['agg_ipc']:.2f}" if r['agg_ipc'] is not None else '—'
                    p = "✓" if r['passed'] else "✗"
                    print(f"{query:<6} {config:<6} {T:>4} "
                          f"{fms:>12} {ams:>12} {ts:>10} "
                          f"{rf:>6} {ra:>6} {rd:>8} {md:>7} {le:>5} "
                          f"{ws:>7} {ct:>6} {str(ch):>6} "
                          f"{fllc:>7} {fipc:>6} {allc:>7} {aipc:>6} {p:>5}")
            print()


def main():
    records = collect_all_logs()
    print(f"Parsed {len(records)} Party B log files\n")

    if not records:
        print("ERROR: No logs found!", file=sys.stderr)
        sys.exit(1)

    # Write CSV
    csv_path = os.path.join(E5_DIR, 'e5_full_results.csv')
    write_csv(records, csv_path)

    # Print all tables
    print_full_sweep_table(records)
    print_table1_filter(records)
    print_table2_agg(records)
    print_table3_auto_validation(records)
    print_summary(records)
    print_portability(records)


if __name__ == '__main__':
    main()
