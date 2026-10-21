"""Local PHP runtime discovery and inspection."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from .advisory import CVES, assess_version, parse_version
from .models import Confidence, Finding, ScanReport, Status

PHP_INFO_CODE = r"""echo json_encode([
 "version" => PHP_VERSION,
 "sapi" => PHP_SAPI,
 "binary" => PHP_BINARY,
 "ini" => php_ini_loaded_file() ?: null,
 "memory_limit" => ini_get("memory_limit"),
 "session_upload_progress" => ini_get("session.upload_progress.enabled"),
 "fatal_error_backtraces" => ini_get("fatal_error_backtraces"),
], JSON_UNESCAPED_SLASHES);"""


def discover_binaries() -> tuple[str, ...]:
    candidates: set[str] = set()
    for name in ("php", "php8.2", "php8.3", "php8.4", "php8.5"):
        binary = shutil.which(name)
        if binary:
            candidates.add(binary)
    search_dirs = {Path(item) for item in os.environ.get("PATH", "").split(os.pathsep) if item}
    search_dirs.update((Path("/usr/bin"), Path("/usr/local/bin"), Path("/opt/homebrew/bin")))
    for directory in search_dirs:
        try:
            entries = directory.iterdir()
        except OSError:
            continue
        for entry in entries:
            if re.fullmatch(r"php(?:\d+(?:\.\d+)?)?", entry.name) and os.access(entry, os.X_OK):
                candidates.add(str(entry))
    return tuple(sorted({str(Path(item).resolve()) for item in candidates}))


def _command(args: list[str], timeout: float = 5.0) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(  # noqa: S603 - arguments are passed without a shell
            args, check=False, capture_output=True, text=True, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def package_revision(binary: str) -> str | None:
    """Return best-effort package provenance without assuming a backport is fixed."""
    resolved = str(Path(binary).resolve())
    if shutil.which("dpkg-query"):
        owner = _command(["dpkg-query", "-S", resolved])
        if owner and owner.returncode == 0 and ":" in owner.stdout:
            package = owner.stdout.split(":", 1)[0].strip()
            version = _command(["dpkg-query", "-W", "-f=${Package} ${Version}", package])
            if version and version.returncode == 0:
                return version.stdout.strip()
    if shutil.which("rpm"):
        result = _command(
            ["rpm", "-qf", "--qf", "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}", resolved]
        )
        if result and result.returncode == 0:
            return result.stdout.strip()
    if shutil.which("apk"):
        result = _command(["apk", "info", "--who-owns", resolved])
        if result and result.returncode == 0:
            return result.stdout.strip()
    return None


def inspect_binary(binary: str) -> Finding:
    result = _command([binary, "-r", PHP_INFO_CODE])
    if result is None:
        return Finding(
            binary,
            Status.ERROR,
            Confidence.HIGH,
            "PHP inspection failed",
            "The binary could not be executed or timed out.",
            cves=CVES,
        )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:500]
        return Finding(
            binary,
            Status.ERROR,
            Confidence.HIGH,
            "PHP inspection failed",
            detail or f"PHP exited with status {result.returncode}.",
            cves=CVES,
        )
    try:
        info = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return Finding(
            binary,
            Status.ERROR,
            Confidence.HIGH,
            "PHP returned invalid inspection data",
            result.stdout[:500],
            cves=CVES,
        )
    version = parse_version(str(info.get("version", "")))
    if not version:
        return Finding(
            binary,
            Status.ERROR,
            Confidence.HIGH,
            "PHP version was not recognized",
            str(info.get("version")),
            cves=CVES,
        )
    canonical = str(Path(binary).resolve())
    package = package_revision(canonical)
    metadata = {
        "runtime": info,
        "temporary_mitigation_observations": {
            "memory_limit_unlimited": str(info.get("memory_limit")) == "-1",
            "session_upload_progress_disabled": str(info.get("session_upload_progress"))
            in {"", "0"},
            "fatal_error_backtraces_disabled": str(info.get("fatal_error_backtraces")) in {"", "0"},
        },
    }
    return assess_version(
        version,
        target=canonical,
        source="executed local PHP binary",
        package_revision=package,
        metadata=metadata,
    )


def scan_local(binaries: list[str] | None = None) -> ScanReport:
    selected = tuple(binaries) if binaries else discover_binaries()
    if not selected:
        return ScanReport(
            "local",
            (),
            errors=("No PHP binary was found; use --php-bin for a nonstandard path.",),
        )
    findings = tuple(inspect_binary(item) for item in dict.fromkeys(selected))
    errors = tuple(item.detail for item in findings if item.status is Status.ERROR)
    notes = (
        "Configuration mitigations are observations only; updating is the only "
        "complete mitigation.",
    )
    return ScanReport("local", findings, errors, notes)
