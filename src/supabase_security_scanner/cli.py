from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from .config import ScanConfig
from .models import Severity
from .scanner import SecurityScanner


_SEVERITY_EXIT_ORDER = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="supa-sec",
        description="Run deterministic, read-only Supabase security checks locally.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Scan a Supabase project and optional local source directory.")
    scan.add_argument("--project-ref", help="Overrides SUPABASE_PROJECT_REF. Never pass credentials as CLI flags.")
    scan.add_argument("--source-dir", type=Path, help="Overrides SUPABASE_SCANNER_SOURCE_DIR.")
    scan.add_argument("--output", type=Path, help="Write JSON findings to this local file.")
    scan.add_argument("--format", choices=("json", "text"), default="json")
    scan.add_argument(
        "--allow-public-bucket",
        action="append",
        default=[],
        help="Add a bucket name that is intentionally public. Can be repeated.",
    )
    scan.add_argument(
        "--max-rate-limit",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Flag an Auth rate limit above your chosen policy. Can be repeated.",
    )
    scan.add_argument(
        "--fail-on",
        choices=tuple(_SEVERITY_EXIT_ORDER),
        help="Exit non-zero when a finding meets or exceeds this severity.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        return 2
    rate_limits = _parse_rate_limits(args.max_rate_limit)
    base_config = ScanConfig.from_environment()
    allowlist = (
        base_config.public_bucket_allowlist.union(args.allow_public_bucket)
        if args.allow_public_bucket
        else base_config.public_bucket_allowlist
    )
    config = base_config.with_overrides(
        project_ref=args.project_ref,
        source_dir=args.source_dir.expanduser() if args.source_dir else None,
        public_bucket_allowlist=frozenset(allowlist),
        max_auth_rate_limits=rate_limits,
    )
    payload = SecurityScanner().scan(config).to_dict()
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        args.output.expanduser().write_text(rendered + "\n", encoding="utf-8")
    if args.format == "json":
        print(rendered)
    else:
        _print_text(payload)
    return _exit_code(payload, args.fail_on)


def _parse_rate_limits(values: list[str]) -> dict[str, int]:
    parsed: dict[str, int] = {}
    for value in values:
        name, separator, raw_number = value.partition("=")
        if not separator or not name.startswith("rate_limit_"):
            raise SystemExit("--max-rate-limit must use rate_limit_name=positive_integer")
        try:
            number = int(raw_number)
        except ValueError as error:
            raise SystemExit("--max-rate-limit value must be an integer") from error
        if number < 1:
            raise SystemExit("--max-rate-limit value must be positive")
        parsed[name] = number
    return parsed


def _print_text(payload: dict) -> None:
    findings = payload["findings"]
    print(f"Supabase Security Scanner: {len(findings)} finding(s)")
    for finding in findings:
        print(f"[{finding['severity'].upper()}] {finding['id']} {finding['resource']}: {finding['issue']}")
    for warning in payload["warnings"]:
        print(f"[WARNING] {warning}")


def _exit_code(payload: dict, fail_on: str | None) -> int:
    if not fail_on:
        return 0
    threshold = _SEVERITY_EXIT_ORDER[fail_on]
    return int(any(_SEVERITY_EXIT_ORDER[finding["severity"]] >= threshold for finding in payload["findings"]))


if __name__ == "__main__":
    raise SystemExit(main())
