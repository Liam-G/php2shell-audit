import json

from php2shell_audit.advisory import assess_version
from php2shell_audit.models import PhpVersion, ScanReport
from php2shell_audit.reporting import render


def report() -> ScanReport:
    finding = assess_version(PhpVersion(8, 2, 34), target="php", source="test")
    return ScanReport("version", (finding,))


def test_json_has_stable_schema_and_cves() -> None:
    data = json.loads(render(report(), "json"))
    assert data["schema_version"] == "1.0"
    assert data["summary"]["affected"] == 1
    assert data["findings"][0]["cves"] == ["CVE-2026-109618", "CVE-2026-109619"]


def test_sarif_contains_result_and_rule() -> None:
    data = json.loads(render(report(), "sarif"))
    run = data["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["id"] == "PHP2SHELL-AFFECTED-VERSION"
    assert len(run["results"]) == 1


def test_text_contains_remediation() -> None:
    text = render(report(), "text")
    assert "[AFFECTED]" in text
    assert "fix:" in text
