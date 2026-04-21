#!/usr/bin/env python3
"""
parse_e5.py — Parse E5 (SMT Policy Portability) Party B logs into CSV.

Scans data/paper_runs/E5/<server>/ for *_party_b.log files.
Extracts from filename: query, config (old/new/auto), T
Extracts from log: ring_dim, mult_depth, rho, T_policy, operator timings, total runtime.

Usage:
  python3 scripts/HAMMER/parse_e5.py [--data_dir ./data/paper_runs/E5]
"""
import re, os, csv, argparse, glob, sys


def parse_log(path):
    """Extract key metrics from a single Party B log file."""
    result = {}
    with open(path) as f:
        content = f.read()

    # ring_dim, mult_depth
    m = re.search(r'ring_dim=(\d+)\s+mult_depth=(\d+)', content)
    if m:
        result['ring_dim'] = int(m.group(1))
        result['mult_depth'] = int(m.group(2))

    # Filter SMT decision
    m = re.search(r'\[QueryPlan/Filter\] SMT: rho=([\d.]+) -> T\*=(\d+)', content)
    if m:
        result['rho_filter'] = float(m.group(1))
        result['T_filter_policy'] = int(m.group(2))

    # Agg SMT decision (new rotation-bound format or old format)
    m = re.search(r'\[QueryPlan/Agg\] SMT: rho=([\d.]+) -> T\*=(\d+)', content)
    if m:
        result['rho_agg'] = float(m.group(1))
        result['T_agg_policy'] = int(m.group(2))

    # Filter override
    m = re.search(r'\[QueryPlan/Filter\] OVERRIDE:.*?T=(\d+)', content)
    if m:
        result['T_filter_policy'] = int(m.group(1))

    # Agg override
    m = re.search(r'\[QueryPlan/Agg\] OVERRIDE:.*?T=(\d+)', content)
    if m:
        result['T_agg_policy'] = int(m.group(1))

    # Operator timing
    m = re.search(r'\[Timing\] Operator #\d+ \(FheFilter\): ([\d.]+) ms', content)
    if m:
        result['filter_ms'] = float(m.group(1))

    m = re.search(r'\[Timing\] Operator #\d+ \(FheAggregate\): ([\d.]+) ms', content)
    if m:
        result['agg_ms'] = float(m.group(1))

    # Total runtime
    m = re.search(r'\[FheTpchTest\] Runtime: ([\d.]+) sec', content)
    if m:
        result['total_ms'] = float(m.group(1)) * 1000.0

    # P, H, L3
    m = re.search(r'P=(\d+) H=(\d+).*?L3=(\d+)MB', content)
    if m:
        result['P'] = int(m.group(1))
        result['H'] = int(m.group(2))
        result['L3_mb'] = int(m.group(3))

    # PASSED/FAILED
    result['passed'] = bool(re.search(r'\[\s+PASSED\s+\]', content) or
                            re.search(r'\[\s+OK\s+\]', content))

    return result


def parse_filename(fname):
    """Extract config, query, sf, T from E5 filename.
    Examples:
      e5_old_q1_sf_0.1_T6_party_b.log  -> (old, q1, sf_0.1, 6)
      e5_auto_q5_sf_0.1_party_b.log    -> (auto, q5, sf_0.1, None)
    """
    # config
    m = re.match(r'e5_(old|new|auto)_', fname)
    config = m.group(1) if m else 'unknown'

    # query
    m = re.search(r'e5_\w+_(q\d+(?:_one_sum)?)', fname)
    query = m.group(1) if m else 'unknown'

    # sf
    m = re.search(r'(sf_[\d.]+)', fname)
    sf = m.group(1) if m else 'unknown'

    # T (thread count from filename)
    m = re.search(r'_T(\d+)_party', fname)
    T = int(m.group(1)) if m else None

    return config, query, sf, T


def main():
    parser = argparse.ArgumentParser(description='Parse E5 experiment logs into CSV')
    parser.add_argument('--data_dir', default='./data/paper_runs/E5',
                        help='Root E5 directory containing per-server subdirs')
    args = parser.parse_args()

    if not os.path.exists(args.data_dir):
        print(f"Error: {args.data_dir} not found")
        sys.exit(1)

    fields = ['server', 'query', 'config', 'sf', 'T',
              'ring_dim', 'mult_depth',
              'rho_filter', 'rho_agg',
              'T_filter_policy', 'T_agg_policy',
              'filter_ms', 'agg_ms', 'total_ms',
              'P', 'H', 'L3_mb', 'passed', 'log_file']

    warnings = []

    for server_dir in sorted(glob.glob(f"{args.data_dir}/*")):
        if not os.path.isdir(server_dir):
            continue
        server = os.path.basename(server_dir)
        out_csv = os.path.join(server_dir, 'e5_results.csv')
        rows = []

        for log_path in sorted(glob.glob(f"{server_dir}/e5_*_party_b.log")):
            fname = os.path.basename(log_path)
            config, query, sf, T = parse_filename(fname)
            data = parse_log(log_path)

            data['server'] = server
            data['query'] = query
            data['config'] = config
            data['sf'] = sf
            data['T'] = T if T is not None else 'auto'
            data['log_file'] = fname

            # Flag auto runs where T_agg_policy != H
            if config == 'auto' and 'T_agg_policy' in data and 'H' in data:
                if data['T_agg_policy'] != data['H']:
                    warnings.append(
                        f"  WARN: {fname}: T_agg_policy={data['T_agg_policy']} != H={data['H']}")

            rows.append(data)

        if not rows:
            print(f"  {server}: no E5 logs found")
            continue

        with open(out_csv, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            w.writeheader()
            w.writerows(rows)

        n_passed = sum(1 for r in rows if r.get('passed'))
        print(f"  {server}: {len(rows)} runs ({n_passed} passed) -> {out_csv}")

    if warnings:
        print("\nAgg policy warnings (T_agg != H):")
        for w in warnings:
            print(w)


if __name__ == '__main__':
    main()
