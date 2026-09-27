"""
SecureMailScope — Test PCAP Generator
Phase 0 STUB — structure and CLI only. Scenarios implemented in Phase 15.

Usage:
    python generate_pcap.py --scenario 1 --output ./pcaps/scenario_01.pcap
    python generate_pcap.py --all --output-dir ./pcaps/
    python generate_pcap.py --list

Scenarios:
    1  — Normal secure SMTP (TLS 1.3, ECDHE, valid cert, full chain)
    2  — Weak TLS version (TLS 1.0 negotiated)
    3  — Weak cipher suite (RC4-128)
    4  — Expired certificate (at capture time)
    5  — Self-signed certificate
    6  — Broken/incomplete certificate chain
    7  — No Forward Secrecy (RSA key exchange)
    8  — STARTTLS security failure (accepted, TLS not followed)
    9  — Truncated capture (handshake incomplete)
    10 — Fleet drift (baseline + changed cryptographic configuration)
"""

import argparse
import sys
import os
from pathlib import Path

# Scenario registry — populated in Phase 15
SCENARIOS = {
    1:  ("Normal secure SMTP — TLS 1.3, ECDHE, valid cert", None),
    2:  ("Weak TLS version — TLS 1.0 negotiated", None),
    3:  ("Weak cipher suite — RC4-128", None),
    4:  ("Expired certificate at capture time", None),
    5:  ("Self-signed certificate", None),
    6:  ("Broken / incomplete certificate chain", None),
    7:  ("No Forward Secrecy — RSA key exchange", None),
    8:  ("STARTTLS failure — accepted but TLS not followed", None),
    9:  ("Truncated capture — handshake incomplete", None),
    10: ("Fleet drift — baseline + changed cryptographic configuration", None),
}


def list_scenarios() -> None:
    print("\nSecureMailScope — Available Test PCAP Scenarios")
    print("=" * 56)
    for num, (description, _fn) in SCENARIOS.items():
        status = "[ STUB — Phase 15 ]" if _fn is None else "[ READY ]"
        print(f"  {num:>2}  {status}  {description}")
    print()


def generate_scenario(scenario_num: int, output_path: Path) -> bool:
    """
    Dispatcher for scenario generators.
    Returns True on success, False on failure.
    """
    if scenario_num not in SCENARIOS:
        print(f"Error: Scenario {scenario_num} is not defined.", file=sys.stderr)
        return False

    description, generator_fn = SCENARIOS[scenario_num]

    if generator_fn is None:
        print(
            f"Scenario {scenario_num} ({description}) is not yet implemented.\n"
            f"This stub will be replaced in Phase 15.",
            file=sys.stderr,
        )
        return False

    print(f"Generating scenario {scenario_num}: {description}")
    print(f"Output: {output_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    generator_fn(str(output_path))

    print(f"Done. PCAP written to: {output_path}")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SecureMailScope Test PCAP Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List all available scenarios",
    )
    parser.add_argument(
        "--scenario", "-s",
        type=int,
        choices=list(SCENARIOS.keys()),
        help="Scenario number to generate",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Output PCAP file path",
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Generate all available (implemented) scenarios",
    )
    parser.add_argument(
        "--output-dir", "-d",
        type=Path,
        default=Path("./pcaps"),
        help="Output directory for --all (default: ./pcaps/)",
    )

    args = parser.parse_args()

    if args.list:
        list_scenarios()
        return

    if args.all:
        success_count = 0
        for num, (description, fn) in SCENARIOS.items():
            if fn is None:
                continue  # Skip stubs
            output = args.output_dir / f"scenario_{num:02d}.pcap"
            if generate_scenario(num, output):
                success_count += 1
        print(f"\nGenerated {success_count} / {len(SCENARIOS)} scenarios.")
        return

    if args.scenario is None:
        parser.print_help()
        print("\nNote: All scenarios are currently stubs (Phase 15). Use --list to see them.")
        return

    output = args.output or Path(f"./pcaps/scenario_{args.scenario:02d}.pcap")
    generate_scenario(args.scenario, output)


if __name__ == "__main__":
    main()
