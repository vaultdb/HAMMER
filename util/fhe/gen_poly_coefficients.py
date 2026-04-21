#!/usr/bin/env python3
# gen_poly_coeffs.py
# Generate Lagrange interpolation coefficients for FHE comparator polynomial.
# Target: P(z) = 1 if z > 0, P(z) = 0 if z <= 0 (mod p), over range -RANGE to +RANGE.
#
# Usage:
#   python3 gen_poly_coefficients.py [RANGE]   # Single range (e.g., 3 for Base 4, 15 for Base 16, 63 for Base 64)
#   python3 gen_poly_coefficients.py --all     # Generate for Base 4 (RANGE=3), Base 16 (RANGE=15), Base 64 (RANGE=63)

import argparse
import sys


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    d, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return d, x, y


def modinv(a, m):
    d, x, y = extended_gcd(a, m)
    if d != 1:
        raise Exception("modular inverse does not exist")
    return x % m


def poly_mult_by_linear(poly, c, p):
    """Multiply polynomial (list of coeffs, poly[0]=const) by (x - c) mod p."""
    result = [0] * (len(poly) + 1)
    for k in range(len(poly)):
        result[k] = (result[k] - c * poly[k]) % p
        result[k + 1] = (result[k + 1] + poly[k]) % p
    return result


def _lagrange_interpolate(p, x_vals, y_vals):
    """Core Lagrange interpolation: given (x_i, y_i), return coeffs of poly P s.t. P(x_i)=y_i."""
    n = len(x_vals)
    result = [0] * n
    for i in range(n):
        xi, yi = x_vals[i], y_vals[i]
        if yi == 0:
            continue
        denom = 1
        for j in range(n):
            if i == j:
                continue
            term = (xi - x_vals[j]) % p
            denom = (denom * term) % p
        inv_denom = modinv(denom, p)
        poly_i = [1]
        for j in range(n):
            if i == j:
                continue
            poly_i = poly_mult_by_linear(poly_i, x_vals[j], p)
        scale = (yi * inv_denom) % p
        for k in range(len(poly_i)):
            result[k] = (result[k] + scale * poly_i[k]) % p
    return result


def interpolate(p, range_val):
    """
    Lagrange interpolation over Z/pZ.
    Comparison range: -range_val to +range_val
    Target: P(x) = 1 if x > 0, P(x) = 0 if x <= 0 (GT polynomial)
    """
    x_vals = []
    y_vals = []

    # x = 0 and negative -> 0
    for i in range(range_val + 1):
        val = (-i) % p
        x_vals.append(val)
        y_vals.append(0)

    # x positive -> 1
    for i in range(1, range_val + 1):
        x_vals.append(i)
        y_vals.append(1)

    return _lagrange_interpolate(p, x_vals, y_vals)


def interpolate_R(p, range_val):
    """
    Lagrange interpolation for Phase C composite polynomial R(z).
    R(z): z < 0 -> 0, z = 0 -> 1, z > 0 -> 2
    Same domain as GT: -range_val to +range_val.
    """
    x_vals = []
    y_vals = []

    # x = 0 -> 1; x negative -> 0
    for i in range(range_val + 1):
        val = (-i) % p
        x_vals.append(val)
        y_vals.append(1 if i == 0 else 0)

    # x positive -> 2
    for i in range(1, range_val + 1):
        x_vals.append(i)
        y_vals.append(2)

    return _lagrange_interpolate(p, x_vals, y_vals)


# Preset ranges for common radix bases
PRESETS = {
    3: "Base 4",   # radix 4: values 0..3, diff range +/- 3, degree 6
    15: "Base 16", # radix 16: values 0..15, diff range +/- 15, degree 30
    63: "Base 64", # radix 64: values 0..63, diff range +/- 63, degree 126
}


def format_coeffs_for_cpp(coeffs, p=65537):
    """Return coefficients as mod p values (0..p-1) for C++ BFV MakePackedPlaintext."""
    return [c % p for c in coeffs]


def generate_and_print(p, range_val, label=None):
    """Generate coefficients for given range and print in C++ format."""
    if label is None:
        label = PRESETS.get(range_val, f"Range +/- {range_val}")
    print(f"\n========== {label} (RANGE={range_val}) ==========")
    coeffs = interpolate(p, range_val)

    # Trim trailing zeros
    while len(coeffs) > 1 and coeffs[-1] == 0:
        coeffs.pop()
    degree = len(coeffs) - 1
    print(f"Degree: {degree}")
    print(f"Number of coefficients: {len(coeffs)}")
    cpp_coeffs = format_coeffs_for_cpp(coeffs, p)

    print("// C++ array (mod p, 0..65536):")
    print("static const int64_t coeffs[] = {")
    for i in range(0, len(cpp_coeffs), 10):
        chunk = cpp_coeffs[i : i + 10]
        line = "    " + ", ".join(str(c) for c in chunk)
        if i + 10 < len(cpp_coeffs):
            line += ","
        print(line)
    print("};")

    # Single-line copy-paste
    cpp_str = ", ".join(str(c) for c in cpp_coeffs)
    print(f"\n// One-liner: {{ {cpp_str} }}")
    return coeffs


def generate_and_print_R(p, range_val, label=None):
    """Generate R(z) coefficients: z<0->0, z=0->1, z>0->2. For Phase C."""
    if label is None:
        label = PRESETS.get(range_val, f"Range +/- {range_val}")
    print(f"\n========== R(z) {label} (RANGE={range_val}) [Phase C] ==========")
    coeffs = interpolate_R(p, range_val)

    while len(coeffs) > 1 and coeffs[-1] == 0:
        coeffs.pop()
    degree = len(coeffs) - 1
    print(f"Degree: {degree}")
    print(f"Number of coefficients: {len(coeffs)}")
    cpp_coeffs = format_coeffs_for_cpp(coeffs, p)

    suffix = {3: "Base4", 15: "Base16", 63: "Base64"}.get(range_val, f"R{range_val}")
    print(f"// C++ array: coeffs_R_{suffix}")
    print("static const int64_t coeffs[] = {")
    for i in range(0, len(cpp_coeffs), 10):
        chunk = cpp_coeffs[i : i + 10]
        line = "    " + ", ".join(str(c) for c in chunk)
        if i + 10 < len(cpp_coeffs):
            line += ","
        print(line)
    print("};")

    cpp_str = ", ".join(str(c) for c in cpp_coeffs)
    print(f"\n// One-liner: {{ {cpp_str} }}")
    return coeffs


def main():
    parser = argparse.ArgumentParser(
        description="Generate Lagrange interpolation coefficients for FHE comparator (p=65537)."
    )
    parser.add_argument(
        "range_val",
        nargs="?",
        type=int,
        default=None,
        help="RANGE for comparison (e.g., 3=Base4, 15=Base16, 63=Base64)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Generate for Base 4 (3), Base 16 (15), Base 64 (63)",
    )
    parser.add_argument(
        "--R",
        "--r-poly",
        dest="r_poly",
        action="store_true",
        help="Generate R(z) polynomial for Phase C: z<0->0, z=0->1, z>0->2",
    )
    parser.add_argument(
        "--rns",
        action="store_true",
        help="Generate coefficients for all RNS moduli (65537, 786433, 1179649); each p has different coeffs.",
    )
    parser.add_argument(
        "--moduli",
        type=str,
        default=None,
        help="Comma-separated list of prime moduli (e.g. 65537,786433,1179649). Use with --all or RANGE.",
    )
    args = parser.parse_args()

    # Modulus list: default p=65537 only; --rns or --moduli adds 786433, 1179649
    if args.moduli:
        moduli = [int(m.strip()) for m in args.moduli.split(",") if m.strip()]
    elif args.rns:
        moduli = [65537, 786433, 1179649]
    else:
        moduli = [65537]

    gen_fn = generate_and_print_R if args.r_poly else generate_and_print

    if args.all:
        for p in moduli:
            print(f"\n########## Modulus p = {p} ##########")
            for r in (3, 15, 63):
                gen_fn(p, r)
        return

    if args.range_val is None:
        # Default: Base 64 (backward compatible)
        args.range_val = 63

    if args.range_val < 1 or args.range_val > 64:
        print("Error: RANGE should be between 1 and 64", file=sys.stderr)
        sys.exit(1)

    for p in moduli:
        print(f"\n########## Modulus p = {p} ##########")
        gen_fn(p, args.range_val)


if __name__ == "__main__":
    main()
