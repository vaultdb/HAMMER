#!/usr/bin/env python3
"""Generate bit_packing SQL for any TPC-H scale factor.

Usage:
    python3 docker/generate_bit_packing.py --sf=1 > test/support/tpch_unioned_150000-bit_packing.sql
    python3 docker/generate_bit_packing.py --sf=10 > test/support/tpch_unioned_1500000-bit_packing.sql

Optionally query a live PostgreSQL database for p_retailprice and p_comment domain sizes:
    python3 docker/generate_bit_packing.py --sf=1 --db=tpch_unioned_150000
"""

import argparse
import math
import subprocess
import sys


def sf_to_db_size(sf: float) -> int:
    """Map SF to DB size suffix (matching common.sh sf_to_db)."""
    mapping = {0.001: 150, 0.01: 1500, 0.1: 15000, 1: 150000, 10: 1500000}
    return mapping.get(sf, int(sf * 150000))


# TPC-H spec scaling formulas (SF-dependent columns)
# key = (table, column), value = lambda sf -> (min, max, domain_size)
# -1 for min/max means "string column, use domain_size only"
SCALED_COLUMNS = {
    ("customer", "c_custkey"):   lambda sf: (1, int(sf * 150000), int(sf * 150000)),
    ("supplier", "s_suppkey"):   lambda sf: (1, int(sf * 10000), int(sf * 10000)),
    ("supplier", "s_name"):      lambda sf: (-1, -1, int(sf * 10000)),
    ("partsupp", "ps_partkey"):  lambda sf: (1, int(sf * 200000), int(sf * 200000)),
    ("partsupp", "ps_suppkey"):  lambda sf: (1, int(sf * 10000), int(sf * 10000)),
    ("part", "p_partkey"):       lambda sf: (1, int(sf * 200000), int(sf * 200000)),
    ("part", "p_name"):          lambda sf: (-1, -1, int(sf * 200000)),
    ("orders", "o_orderkey"):    lambda sf: (1, int(sf * 6000000), int(sf * 1500000)),
    ("orders", "o_custkey"):     lambda sf: (1, int(sf * 150000), int(sf * 150000)),
    ("lineitem", "l_orderkey"):  lambda sf: (1, int(sf * 6000000), int(sf * 1500000)),
    ("lineitem", "l_partkey"):   lambda sf: (1, int(sf * 200000), int(sf * 200000)),
    ("lineitem", "l_suppkey"):   lambda sf: (1, int(sf * 10000), int(sf * 10000)),
}

# Fixed-domain columns (same across all SFs)
FIXED_COLUMNS = [
    ("customer", "c_nationkey",      0, 24, 25),
    ("customer", "c_mktsegment",    -1, -1, 5),
    ("supplier", "s_nationkey",      0, 24, 25),
    ("partsupp", "ps_availqty",      1, 9999, 9999),
    ("nation",   "n_nationkey",      0, 24, 25),
    ("nation",   "n_name",          -1, -1, 25),
    ("nation",   "n_regionkey",      0, 4, 5),
    ("nation",   "n_comment",       -1, -1, 25),
    ("orders",   "o_orderstatus",   -1, -1, 3),
    ("orders",   "o_orderdate",     8035, 10591, 2557),
    ("orders",   "o_orderpriority", -1, -1, 5),
    ("orders",   "o_orderyear",     1992, 1998, 7),
    ("orders",   "o_shippriority",  0, 0, 1),
    ("lineitem", "l_linenumber",     1, 7, 7),
    ("lineitem", "l_quantity",       1, 50, 50),
    ("lineitem", "l_returnflag",    -1, -1, 3),
    ("lineitem", "l_linestatus",    -1, -1, 2),
    ("lineitem", "l_shipinstruct",  -1, -1, 4),
    ("lineitem", "l_shipmode",      -1, -1, 7),
    ("part",     "p_mfgr",         -1, -1, 5),
    ("part",     "p_brand",        -1, -1, 25),
    ("part",     "p_type",         -1, -1, 150),
    ("part",     "p_size",          1, 50, 50),
    ("part",     "p_container",    -1, -1, 40),
    ("region",   "r_regionkey",     0, 4, 5),
    ("region",   "r_name",         -1, -1, 5),
    ("region",   "r_comment",      -1, -1, 5),
]


def query_db(db_name: str, sql: str) -> str:
    """Run a SQL query against a local PostgreSQL database."""
    try:
        result = subprocess.run(
            ["psql", "-U", "vaultdb", "-d", db_name, "-t", "-A", "-c", sql],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip()
    except Exception:
        return ""


def get_retailprice_range(sf: float, db_name: str = None):
    """Get p_retailprice (min, max, domain_size).

    TPC-H spec: P_RETAILPRICE = (90000 + ((P_PARTKEY/10) mod 20001) + 100 * (P_PARTKEY mod 1000))/100
    The range depends on partkey range. Query DB if available, else use conservative estimate.
    """
    if db_name:
        row = query_db(db_name,
            "SELECT MIN(p_retailprice)::int, MAX(p_retailprice)::int FROM part;")
        if row and "|" in row:
            parts = row.split("|")
            mn, mx = int(parts[0]), int(parts[1])
            return (mn, mx, mx - mn + 1)

    # Conservative estimate from TPC-H price formula
    # min price ~= 900+1 = 901, max depends on SF
    # For SF 0.1: (901, 1919, 2899) from existing bit_packing
    # The formula: price = (90000 + (partkey/10 % 20001) + 100*(partkey%1000)) / 100
    # max partkey = SF*200000
    # Conservative: min=901, max ~ 901 + 200 + ceil(SF*200000/10 % 20001)/100
    # Simplify: use (901, 2099) as upper bound for all SFs (price formula is cyclic mod 20001)
    return (901, 2099, 2099 - 901 + 1)


def get_p_comment_domain(sf: float, db_name: str = None):
    """Get p_comment domain_size. Query DB if available, else estimate."""
    if db_name:
        val = query_db(db_name,
            "SELECT COUNT(DISTINCT p_comment) FROM part;")
        if val:
            return (-1, -1, int(val))

    # Estimate: nearly all comments are unique for large SFs
    num_parts = int(sf * 200000)
    return (-1, -1, num_parts)


def generate_bit_packing_sql(sf: float, db_name: str = None):
    """Generate the complete bit_packing SQL dump."""
    rows = []

    # Scaled columns
    for (table, col), func in SCALED_COLUMNS.items():
        mn, mx, ds = func(sf)
        rows.append((table, col, mn, mx, ds))

    # Fixed columns
    for table, col, mn, mx, ds in FIXED_COLUMNS:
        rows.append((table, col, mn, mx, ds))

    # Special columns that need DB query or estimation
    mn, mx, ds = get_retailprice_range(sf, db_name)
    rows.append(("part", "p_retailprice", mn, mx, ds))

    mn, mx, ds = get_p_comment_domain(sf, db_name)
    rows.append(("part", "p_comment", mn, mx, ds))

    # Sort by table name then column name for consistency
    table_order = ["customer", "supplier", "partsupp", "nation", "orders",
                   "lineitem", "part", "region"]
    def sort_key(r):
        try:
            ti = table_order.index(r[0])
        except ValueError:
            ti = len(table_order)
        return (ti, r[1])

    rows.sort(key=sort_key)

    # Output SQL
    db_size = sf_to_db_size(sf)
    print("--")
    print(f"-- bit_packing for tpch_unioned_{db_size} (SF={sf})")
    print(f"-- Generated by generate_bit_packing.py")
    print("--")
    print("DROP TABLE IF EXISTS bit_packing;")
    print()
    print("SET statement_timeout = 0;")
    print("SET lock_timeout = 0;")
    print("SET idle_in_transaction_session_timeout = 0;")
    print("SET client_encoding = 'UTF8';")
    print("SET standard_conforming_strings = on;")
    print("SELECT pg_catalog.set_config('search_path', '', false);")
    print("SET check_function_bodies = false;")
    print("SET xmloption = content;")
    print("SET client_min_messages = warning;")
    print("SET row_security = off;")
    print()
    print("SET default_tablespace = '';")
    print("SET default_table_access_method = heap;")
    print()
    print("CREATE TABLE public.bit_packing (")
    print("    table_name character varying(25),")
    print("    col_name character varying(25),")
    print("    min integer,")
    print("    max integer,")
    print("    domain_size integer")
    print(");")
    print()
    print("ALTER TABLE public.bit_packing OWNER TO vaultdb;")
    print()
    print("COPY public.bit_packing (table_name, col_name, min, max, domain_size) FROM stdin;")

    for table, col, mn, mx, ds in rows:
        print(f"{table}\t{col}\t{mn}\t{mx}\t{ds}")

    print("\\.")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Generate bit_packing SQL for a TPC-H scale factor")
    parser.add_argument("--sf", type=float, required=True,
                        help="TPC-H scale factor (e.g., 0.1, 1, 10)")
    parser.add_argument("--db", type=str, default=None,
                        help="PostgreSQL database name to query for exact values "
                             "(e.g., tpch_unioned_150000)")
    args = parser.parse_args()

    generate_bit_packing_sql(args.sf, args.db)


if __name__ == "__main__":
    main()
