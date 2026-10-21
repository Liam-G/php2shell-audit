"""Command-line interface."""

from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .advisory import assess_version, parse_version
from .local import scan_local
from .models import ScanReport, Status
from .remote import scan_remote
from .reporting import render

AUTHORIZATION_ACK = "I_HAVE_AUTHORIZATION"


class ConfigurationError(ValueError):
    pass


def _report_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--output", type=Path, help="Write the report to this file")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="php2shell-audit", description="Safe PHP2Shell exposure assessment."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    local = commands.add_parser("local", help="Inspect PHP binaries on this host")
    local.add_argument(
        "--php-bin", action="append", default=[], help="Explicit PHP binary; repeatable"
    )
    _report_options(local)

    remote = commands.add_parser("remote", help="Passively inspect authorized HTTP targets")
    remote.add_argument(
        "--target", action="append", default=[], help="Authorized target URL; repeatable"
    )
    remote.add_argument("--target-file", type=Path, help="Newline-delimited authorized targets")
    remote.add_argument("--timeout", type=float, default=5.0)
    remote.add_argument("--workers", type=int, default=4)
    remote.add_argument("--max-targets", type=int, default=1000)
    remote.add_argument("--allow-insecure-http", action="store_true")
    remote.add_argument("--no-verify-tls", action="store_true")
    remote.add_argument(
        "--dry-run", action="store_true", help="Validate and count targets without traffic"
    )
    remote.add_argument("--acknowledge-authorization", metavar="PHRASE")
    _report_options(remote)

    version = commands.add_parser(
        "version", help="Assess a supplied PHP version without executing PHP"
    )
    version.add_argument("php_version")
    _report_options(version)
    return parser


def _load_targets(path: Path | None) -> list[str]:
    if path is None:
        return []
    if not path.is_file():
        raise ConfigurationError(f"target file does not exist: {path}")
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ConfigurationError(f"target file exceeds 10 MiB: {path}")
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _write_output(content: str, path: Path | None) -> None:
    if path is None:
        print(content, end="")
    else:
        path.write_text(content, encoding="utf-8")


def _execute(args: argparse.Namespace) -> ScanReport:
    if args.command == "local":
        return scan_local(args.php_bin or None)
    if args.command == "version":
        version = parse_version(args.php_version)
        if not version:
            raise ConfigurationError(f"invalid PHP version: {args.php_version!r}")
        finding = assess_version(version, target=args.php_version, source="command-line argument")
        return ScanReport("version", (finding,))

    targets = list(dict.fromkeys([*args.target, *_load_targets(args.target_file)]))
    if not targets:
        raise ConfigurationError("at least one --target or --target-file entry is required")
    if len(targets) > args.max_targets:
        raise ConfigurationError(
            f"target count {len(targets)} exceeds --max-targets {args.max_targets}"
        )
    if not 0 < args.timeout <= 120:
        raise ConfigurationError("--timeout must be greater than 0 and at most 120")
    if not 1 <= args.workers <= 32:
        raise ConfigurationError("--workers must be between 1 and 32")
    if args.dry_run:
        return ScanReport(
            "remote-dry-run",
            (),
            notes=(f"Validated scan plan for {len(targets)} unique targets; no traffic sent.",),
        )
    if args.acknowledge_authorization != AUTHORIZATION_ACK:
        raise ConfigurationError(
            f"remote mode requires --acknowledge-authorization {AUTHORIZATION_ACK}"
        )
    return scan_remote(
        targets,
        timeout=args.timeout,
        workers=args.workers,
        verify_tls=not args.no_verify_tls,
        allow_http=args.allow_insecure_http,
    )


def report_exit_code(report: ScanReport) -> int:
    if report.errors or any(item.status is Status.ERROR for item in report.findings):
        return 1
    if any(item.status is Status.AFFECTED for item in report.findings):
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        report = _execute(args)
        _write_output(render(report, args.format), args.output)
        return report_exit_code(report)
    except (ConfigurationError, OSError, UnicodeError) as exc:
        parser.error(str(exc))
    return 1
