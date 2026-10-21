import gzip
import json
from pathlib import Path

from php2shell_audit.hunt import discover_logs, hunt, scan_log, scan_processes
from php2shell_audit.models import Status
from php2shell_audit.reporting import render


def test_log_indicators_are_hashed_not_disclosed(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    secret_line = b'name="PHP_SESSION_UPLOAD_PROGRESS" secret=do-not-print\n'
    log.write_bytes(secret_line + b"Allowed memory size of 42 bytes exhausted\n")
    findings = scan_log(log, 1024)
    assert [item.metadata["rule_id"] for item in findings] == [
        "PHP2SHELL-IOC-001",
        "PHP2SHELL-IOC-003",
    ]
    output = render(
        hunt([log], [], include_processes=False, max_files=10, max_file_bytes=1024), "json"
    )
    assert "do-not-print" not in output
    assert "line_sha256" in output


def test_gzip_logs_and_byte_limit(tmp_path: Path) -> None:
    log = tmp_path / "php.log.gz"
    with gzip.open(log, "wb") as handle:
        handle.write(b"prefix\nheap-use-after-free\n")
    assert scan_log(log, 1024)[0].confidence.value == "high"
    assert scan_log(log, 3) == ()


def test_log_discovery_is_bounded_and_ignores_missing(tmp_path: Path) -> None:
    (tmp_path / "one.log").write_text("one", encoding="utf-8")
    (tmp_path / "two.log").write_text("two", encoding="utf-8")
    found = discover_logs([tmp_path / "missing"], [tmp_path], max_files=1)
    assert len(found) == 1


def write_process(root: Path, pid: int, parent: int, name: str) -> None:
    directory = root / str(pid)
    directory.mkdir()
    (directory / "comm").write_text(name + "\n", encoding="utf-8")
    (directory / "status").write_text(f"Name:\t{name}\nPPid:\t{parent}\n", encoding="utf-8")


def test_process_lineage_detection(tmp_path: Path) -> None:
    write_process(tmp_path, 100, 1, "php-fpm")
    write_process(tmp_path, 101, 100, "sh")
    write_process(tmp_path, 102, 1, "python3")
    findings = scan_processes(tmp_path)
    assert len(findings) == 1
    assert findings[0].metadata["rule_id"] == "PHP2SHELL-IOC-006"
    assert findings[0].status is Status.AFFECTED


def test_hunt_sarif_uses_indicator_rule(tmp_path: Path) -> None:
    log = tmp_path / "error.log"
    log.write_text("zend_mm_heap corrupted\n", encoding="utf-8")
    report = hunt([log], [], include_processes=False, max_files=10, max_file_bytes=1024)
    sarif = json.loads(render(report, "sarif"))
    assert sarif["runs"][0]["results"][0]["ruleId"] == "PHP2SHELL-INDICATOR"
    assert sarif["runs"][0]["results"][0]["level"] == "warning"
