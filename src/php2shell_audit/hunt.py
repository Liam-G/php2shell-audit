"""Offline indicator hunting for PHP2Shell-related activity."""

from __future__ import annotations

import gzip
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, cast

from .advisory import CVES
from .models import Confidence, Evidence, Finding, ScanReport, Status


@dataclass(frozen=True)
class IndicatorRule:
    rule_id: str
    title: str
    pattern: re.Pattern[bytes]
    confidence: Confidence
    explanation: str


RULES = (
    IndicatorRule(
        "PHP2SHELL-IOC-001",
        "Session upload-progress field observed",
        re.compile(rb"PHP_SESSION_UPLOAD_PROGRESS", re.I),
        Confidence.MEDIUM,
        "The default upload-progress field name appeared in a logged request or audit record.",
    ),
    IndicatorRule(
        "PHP2SHELL-IOC-002",
        "Multipart body supplied a session identifier",
        re.compile(rb"name=[\"']?PHPSESSID[\"']?", re.I),
        Confidence.MEDIUM,
        "A multipart form field supplied PHPSESSID; investigate it with upload-progress activity.",
    ),
    IndicatorRule(
        "PHP2SHELL-IOC-003",
        "PHP memory exhaustion observed",
        re.compile(rb"Allowed memory size of [0-9]+ bytes exhausted", re.I),
        Confidence.LOW,
        "Memory exhaustion is common but relevant to CVE-2026-109618 when attacker-reachable.",
    ),
    IndicatorRule(
        "PHP2SHELL-IOC-004",
        "PHP worker crash or heap corruption observed",
        re.compile(
            rb"zend_mm_heap corrupted|heap corruption|segfault|segmentation fault|"
            rb"child .* exited on signal 11",
            re.I,
        ),
        Confidence.MEDIUM,
        "A worker crash or heap-corruption message warrants PHP2Shell incident triage.",
    ),
    IndicatorRule(
        "PHP2SHELL-IOC-005",
        "Use-after-free diagnostic observed",
        re.compile(rb"heap-use-after-free|AddressSanitizer.*use-after-free", re.I),
        Confidence.HIGH,
        "A memory-safety diagnostic consistent with the public research was observed.",
    ),
)

WEB_WORKERS = re.compile(
    r"^(?:php-fpm(?:\d+(?:\.\d+)?)?|php-cgi|lsphp|litespeed|apache2|httpd|frankenphp)$",
    re.I,
)
SUSPICIOUS_CHILDREN = {
    "bash",
    "curl",
    "dash",
    "nc",
    "ncat",
    "netcat",
    "perl",
    "python",
    "python3",
    "ruby",
    "sh",
    "socat",
    "wget",
    "zsh",
}
HUNT_REMEDIATION = (
    "Preserve the source log and surrounding requests, identify the worker/container, "
    "isolate it if compromise is plausible, and follow the incident-response guidance."
)


def discover_logs(paths: list[Path], directories: list[Path], max_files: int) -> tuple[Path, ...]:
    result: list[Path] = []
    for path in paths:
        if path.is_file():
            result.append(path)
    for directory in directories:
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if path.is_file() and not path.is_symlink():
                result.append(path)
                if len(result) >= max_files:
                    return tuple(dict.fromkeys(result))
    return tuple(dict.fromkeys(result[:max_files]))


def _open_log(path: Path) -> BinaryIO:
    if path.suffix.lower() == ".gz":
        return cast(BinaryIO, gzip.open(path, "rb"))
    return path.open("rb")


def scan_log(path: Path, max_bytes: int) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    consumed = 0
    try:
        with _open_log(path) as handle:
            line_number = 0
            while consumed < max_bytes:
                remaining = max_bytes - consumed
                line = handle.readline(remaining + 1)
                if not line:
                    break
                line_number += 1
                truncated = len(line) > remaining
                if truncated:
                    line = line[:remaining]
                consumed += len(line)
                digest = hashlib.sha256(line.rstrip(b"\r\n")).hexdigest()
                for rule in RULES:
                    if not rule.pattern.search(line):
                        continue
                    findings.append(
                        Finding(
                            target=f"{path}:{line_number}",
                            status=Status.AFFECTED,
                            confidence=rule.confidence,
                            summary=rule.title,
                            detail=rule.explanation,
                            cves=CVES,
                            evidence=(Evidence("line_sha256", digest, str(path)),),
                            remediation=HUNT_REMEDIATION,
                            metadata={
                                "rule_id": rule.rule_id,
                                "line": line_number,
                                "source_size_limit": max_bytes,
                            },
                        )
                    )
                if truncated:
                    break
    except (OSError, EOFError) as exc:
        return (
            Finding(
                str(path),
                Status.ERROR,
                Confidence.LOW,
                "Log could not be inspected",
                str(exc),
                cves=CVES,
            ),
        )
    return tuple(findings)


def _process_table(proc_root: Path) -> dict[int, tuple[int, str]]:
    table: dict[int, tuple[int, str]] = {}
    try:
        entries = tuple(proc_root.iterdir())
    except OSError:
        return table
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            name = (entry / "comm").read_text(encoding="utf-8").strip()
            status = (entry / "status").read_text(encoding="utf-8")
            parent_match = re.search(r"^PPid:\s+(\d+)$", status, re.M)
            if parent_match:
                table[int(entry.name)] = (int(parent_match.group(1)), name)
        except (OSError, UnicodeError, ValueError):
            continue
    return table


def scan_processes(proc_root: Path = Path("/proc")) -> tuple[Finding, ...]:
    table = _process_table(proc_root)
    findings: list[Finding] = []
    for pid, (parent_pid, name) in table.items():
        parent = table.get(parent_pid)
        if (
            name.lower() not in SUSPICIOUS_CHILDREN
            or not parent
            or not WEB_WORKERS.match(parent[1])
        ):
            continue
        findings.append(
            Finding(
                target=f"pid:{pid}",
                status=Status.AFFECTED,
                confidence=Confidence.MEDIUM,
                summary="Suspicious child of a PHP/web worker",
                detail=(
                    f"Process {name!r} is a direct child of {parent[1]!r}. This can be "
                    "legitimate, but should be correlated with request and audit logs."
                ),
                cves=CVES,
                evidence=(
                    Evidence(
                        "process_lineage",
                        f"{parent_pid}:{parent[1]} -> {pid}:{name}",
                        str(proc_root),
                    ),
                ),
                remediation=HUNT_REMEDIATION,
                metadata={
                    "rule_id": "PHP2SHELL-IOC-006",
                    "pid": pid,
                    "parent_pid": parent_pid,
                },
            )
        )
    return tuple(findings)


def hunt(
    paths: list[Path],
    directories: list[Path],
    *,
    include_processes: bool,
    max_files: int,
    max_file_bytes: int,
) -> ScanReport:
    logs = discover_logs(paths, directories, max_files)
    findings = tuple(item for path in logs for item in scan_log(path, max_file_bytes))
    if include_processes:
        findings += scan_processes()
    errors = tuple(
        f"{item.target}: {item.detail}" for item in findings if item.status is Status.ERROR
    )
    return ScanReport(
        "hunt",
        findings,
        errors,
        notes=(
            "Indicators are triage leads, not proof of exploitation or compromise.",
            "Raw log lines and process arguments are never emitted; line evidence is "
            "SHA-256 hashed.",
        ),
        metadata={
            "logs_scanned": len(logs),
            "process_snapshot": include_processes,
            "max_file_bytes": max_file_bytes,
        },
    )
