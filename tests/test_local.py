import json
from subprocess import CompletedProcess
from unittest.mock import patch

from php2shell_audit.local import discover_binaries, inspect_binary, package_revision, scan_local
from php2shell_audit.models import Status


def php_result(version: str = "8.3.35") -> CompletedProcess[str]:
    payload = {
        "version": version,
        "sapi": "cli",
        "binary": "/usr/bin/php",
        "ini": "/etc/php.ini",
        "memory_limit": "128M",
        "session_upload_progress": "1",
        "fatal_error_backtraces": "0",
    }
    return CompletedProcess(["php"], 0, json.dumps(payload), "")


@patch("php2shell_audit.local.package_revision", return_value=None)
@patch("php2shell_audit.local._command")
def test_local_binary_scan(command, _package) -> None:
    command.return_value = php_result()
    finding = inspect_binary("/usr/bin/php")
    assert finding.status is Status.AFFECTED
    assert finding.version == "8.3.35"
    assert finding.metadata["runtime"]["sapi"] == "cli"
    assert not finding.metadata["temporary_mitigation_observations"]["memory_limit_unlimited"]


@patch("php2shell_audit.local.discover_binaries", return_value=())
def test_no_local_php_is_operational_error(_discover) -> None:
    report = scan_local()
    assert report.errors
    assert report.findings == ()


@patch("php2shell_audit.local._command")
def test_invalid_php_output_is_error(command) -> None:
    command.return_value = CompletedProcess(["php"], 0, "not-json", "")
    assert inspect_binary("php").status is Status.ERROR


@patch("php2shell_audit.local.package_revision", return_value=None)
@patch("php2shell_audit.local._command")
def test_php_command_failure_and_timeout(command, _package) -> None:
    command.return_value = CompletedProcess(["php"], 2, "", "bad configuration")
    assert inspect_binary("php").status is Status.ERROR
    command.return_value = None
    assert inspect_binary("php").status is Status.ERROR


@patch("php2shell_audit.local.package_revision", return_value="php8.5-cli 8.5.11-1")
@patch("php2shell_audit.local._command")
def test_package_revision_reduces_confidence(command, _package) -> None:
    command.return_value = php_result("8.5.11")
    finding = inspect_binary("/usr/bin/php")
    assert finding.status is Status.AFFECTED
    assert "backport" in finding.detail


@patch("php2shell_audit.local.Path.iterdir")
@patch("php2shell_audit.local.shutil.which", return_value=None)
def test_discovery_handles_unreadable_paths(_which, iterdir) -> None:
    iterdir.side_effect = OSError("denied")
    assert discover_binaries() == ()


@patch("php2shell_audit.local._command")
@patch("php2shell_audit.local.shutil.which")
def test_debian_package_lookup(which, command) -> None:
    which.side_effect = lambda name: "/usr/bin/dpkg-query" if name == "dpkg-query" else None
    command.side_effect = [
        CompletedProcess([], 0, "php8.4-cli: /usr/bin/php8.4\n", ""),
        CompletedProcess([], 0, "php8.4-cli 8.4.26-1", ""),
    ]
    assert package_revision("/usr/bin/php8.4") == "php8.4-cli 8.4.26-1"
