"""Text, JSON, and SARIF renderers."""

from __future__ import annotations

import json
from typing import Any

from .models import ScanReport, Status


def render_text(report: ScanReport) -> str:
    lines = [
        "php2shell-audit report",
        f"mode: {report.mode}",
        f"targets: {len(report.findings)}",
        f"affected: {report.affected_count}",
        f"unknown: {report.unknown_count}",
        f"errors: {len(report.errors)}",
    ]
    if report.metadata:
        lines.append(f"metadata: {json.dumps(report.metadata, sort_keys=True)}")
    for finding in report.findings:
        lines.extend(
            (
                "",
                f"[{finding.status.value.upper()}] {finding.summary}",
                f"  target: {finding.target}",
                f"  version: {finding.version or 'not detected'}",
                f"  confidence: {finding.confidence.value}",
                f"  detail: {finding.detail}",
            )
        )
        if finding.remediation:
            lines.append(f"  fix: {finding.remediation}")
        for evidence in finding.evidence:
            lines.append(f"  evidence: {evidence.kind}={evidence.value} ({evidence.source})")
    if report.errors:
        lines.extend(("", "errors:"))
        lines.extend(f"  - {item}" for item in report.errors)
    if report.notes:
        lines.extend(("", "notes:"))
        lines.extend(f"  - {item}" for item in report.notes)
    return "\n".join(lines) + "\n"


def render_sarif(report: ScanReport) -> str:
    version_rule = {
        "id": "PHP2SHELL-AFFECTED-VERSION",
        "name": "Affected PHP2Shell version",
        "shortDescription": {"text": "PHP version affected by CVE-2026-109618 and CVE-2026-109619"},
        "helpUri": "https://www.php.net/",
        "help": {"text": "Upgrade PHP to a fixed release and restart all workers."},
        "properties": {"security-severity": "9.2", "tags": ["security", "cve"]},
    }
    indicator_rule = {
        "id": "PHP2SHELL-INDICATOR",
        "name": "Potential PHP2Shell indicator",
        "shortDescription": {"text": "Potential PHP2Shell activity requires triage"},
        "help": {
            "text": "Preserve evidence and correlate with request, worker, and host telemetry."
        },
        "properties": {"tags": ["security", "incident-response", "cve"]},
    }
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        if finding.status is not Status.AFFECTED:
            continue
        rule_id = (
            "PHP2SHELL-INDICATOR"
            if str(finding.metadata.get("rule_id", "")).startswith("PHP2SHELL-IOC-")
            else "PHP2SHELL-AFFECTED-VERSION"
        )
        location: dict[str, Any] = {
            "physicalLocation": {"artifactLocation": {"uri": finding.target}}
        }
        line_number = finding.metadata.get("line")
        if isinstance(line_number, int):
            source_uri = finding.evidence[0].source if finding.evidence else finding.target
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": source_uri},
                    "region": {"startLine": line_number},
                }
            }
        results.append(
            {
                "ruleId": rule_id,
                "level": "warning" if rule_id == "PHP2SHELL-INDICATOR" else "error",
                "message": {
                    "text": (
                        f"{finding.summary}: {finding.target}. {finding.detail}"
                        if finding.version is None
                        else f"{finding.summary}: {finding.target} reports PHP "
                        f"{finding.version}. {finding.detail}"
                    )
                },
                "locations": [location],
                "properties": finding.as_dict(),
                "partialFingerprints": {
                    "targetEvidence": (
                        f"{finding.target}|{finding.version}|{finding.metadata.get('rule_id', '')}"
                    )
                },
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "php2shell-audit",
                        "rules": [version_rule, indicator_rule],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"


def render(report: ScanReport, output_format: str) -> str:
    if output_format == "text":
        return render_text(report)
    if output_format == "sarif":
        return render_sarif(report)
    return json.dumps(report.as_dict(), indent=2) + "\n"
