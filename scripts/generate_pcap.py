"""
SecureMailScope — Realistic Forensic Test Laboratory PCAP Generator CLI
Phase 9 — Production-grade CLI harness for scenario PCAP generation.

Usage:
    python scripts/generate_pcap.py --scenario 1 --output ./pcaps/scenario_01.pcap
    python scripts/generate_pcap.py --all --output-dir ./pcaps/
    python scripts/generate_pcap.py --list
"""

import argparse
import sys
import os
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.pcap_lab.scenarios import LAB_SCENARIOS


def list_scenarios() -> None:
    print("\nSecureMailScope — Realistic Forensic Test Laboratory Scenarios (Phase 9)")
    print("=" * 70)
    for num, sc in LAB_SCENARIOS.items():
        print(f"  {num:>2}  [ READY ]  {sc.name}")
        print(f"       -> Protocol: {sc.intended_protocol} | Rule(s): {', '.join(sc.expected_rule_ids) if sc.expected_rule_ids else 'None'}")
    print()


def generate_scenario(scenario_num: int, output_path: Path) -> bool:
    """
    Dispatcher for scenario generators.
    Writes real binary PCAP bytes to output_path.
    """
    if scenario_num not in LAB_SCENARIOS:
        print(f"Error: Scenario {scenario_num} is not defined.", file=sys.stderr)
        return False

    sc = LAB_SCENARIOS[scenario_num]
    print(f"Generating scenario {scenario_num}: {sc.name}")
    print(f"Output: {output_path}")

    pcap_bytes = sc.generator_fn()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(pcap_bytes)

    print(f"Done. {len(pcap_bytes)} bytes written to: {output_path}")
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
        choices=list(LAB_SCENARIOS.keys()),
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
        help="Generate all available scenarios",
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
        for num in LAB_SCENARIOS.keys():
            output = args.output_dir / f"scenario_{num:02d}.pcap"
            if generate_scenario(num, output):
                success_count += 1
        print(f"\nGenerated {success_count} / {len(LAB_SCENARIOS)} scenarios.")
        return

    if args.scenario is None:
        parser.print_help()
        print("\nUse --list to see all available forensic laboratory scenarios.")
        return

    output = args.output or Path(f"./pcaps/scenario_{args.scenario:02d}.pcap")
    generate_scenario(args.scenario, output)


if __name__ == "__main__":
    main()
