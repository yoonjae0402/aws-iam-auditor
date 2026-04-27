"""
AWS IAM Security Auditor — command-line entry point.

Usage:
    # Mock mode (no AWS credentials needed)
    python -m src.cli --mock

    # Real AWS (credentials must be configured via environment or ~/.aws)
    python -m src.cli

    # Control output format and destination
    python -m src.cli --mock --format json --output-dir ./reports

Options:
    --mock          Use moto-mocked IAM data (no real AWS credentials needed).
    --output-dir    Directory for report files (default: ./sample_output).
    --format        json | html | both  (default: both).
    --inactive-days Inactivity threshold in days for the inactive-users check (default: 180).
    --key-days      Key-age threshold in days for the unused-keys check (default: 90).
"""

from __future__ import annotations

import argparse
import sys
import os
from pathlib import Path

import boto3


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-iam-auditor",
        description="Scan AWS IAM for common security misconfigurations.",
    )
    p.add_argument(
        "--mock",
        action="store_true",
        help="Use moto-mocked IAM instead of real AWS credentials.",
    )
    p.add_argument(
        "--output-dir",
        default="./sample_output",
        metavar="DIR",
        help="Directory to write report files (default: ./sample_output).",
    )
    p.add_argument(
        "--format",
        choices=["json", "html", "both"],
        default="both",
        help="Report format to generate (default: both).",
    )
    p.add_argument(
        "--key-days",
        type=int,
        default=90,
        metavar="N",
        help="Flag access keys older than N days (default: 90).",
    )
    p.add_argument(
        "--inactive-days",
        type=int,
        default=180,
        metavar="N",
        help="Flag users inactive for more than N days (default: 180).",
    )
    return p


def _run_mock(args) -> None:
    """Run the full audit inside a moto-mocked IAM environment."""
    from moto import mock_aws
    from mock_data.generate_mock import setup_mock_iam
    from src.auditor import IAMAuditor
    from src.reporter import generate_json, generate_html, print_table

    print("  [mock] Starting moto-mocked IAM environment...")

    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        setup_mock_iam(iam)

        auditor = IAMAuditor(
            iam,
            unused_key_days=args.key_days,
            inactive_user_days=args.inactive_days,
        )
        auditor.run_all_checks()
        result = auditor.to_dict()
        result["account_id"] = "123456789012 (mock)"

        _write_reports(result, args)


def _run_real(args) -> None:
    """Run the audit against real AWS using the configured credentials."""
    from src.auditor import IAMAuditor
    from src.reporter import generate_json, generate_html, print_table

    print("  [aws] Connecting to real AWS IAM...")

    iam = boto3.client("iam")

    # Resolve the account ID for the report header.
    try:
        sts = boto3.client("sts")
        account_id = sts.get_caller_identity()["Account"]
    except Exception:
        account_id = "unknown"

    auditor = IAMAuditor(
        iam,
        unused_key_days=args.key_days,
        inactive_user_days=args.inactive_days,
    )
    auditor.run_all_checks()
    result = auditor.to_dict()
    result["account_id"] = account_id

    _write_reports(result, args)


def _write_reports(result: dict, args) -> None:
    from src.reporter import generate_json, generate_html, print_table

    output_dir = Path(args.output_dir)
    fmt = args.format

    # Always print the console table.
    print_table(result)

    if fmt in ("json", "both"):
        path = generate_json(result, output_dir / "sample_report.json")
        print(f"  [json] Report written → {path.resolve()}")

    if fmt in ("html", "both"):
        path = generate_html(result, output_dir / "sample_report.html")
        print(f"  [html] Report written → {path.resolve()}")

    print()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.mock:
            _run_mock(args)
        else:
            _run_real(args)
    except KeyboardInterrupt:
        print("\nAborted.")
        return 1
    except Exception as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
