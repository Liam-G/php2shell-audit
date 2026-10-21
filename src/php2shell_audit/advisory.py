"""Published PHP2Shell version boundaries and version assessment."""

from __future__ import annotations

import re

from .models import Confidence, Evidence, Finding, PhpVersion, Status

CVES = ("CVE-2026-109618", "CVE-2026-109619")
FIXED_RELEASES: dict[tuple[int, int], PhpVersion] = {
    (8, 2): PhpVersion(8, 2, 35),
    (8, 3): PhpVersion(8, 3, 36),
    (8, 4): PhpVersion(8, 4, 27),
    (8, 5): PhpVersion(8, 5, 12),
}
VERSION_PATTERN = re.compile(
    r"(?<!\d)(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?P<suffix>(?:[-+~][0-9A-Za-z.+:~_-]+|[A-Za-z][0-9A-Za-z.-]*)?)(?!\d)"
)
REMEDIATION = (
    "Upgrade to PHP 8.2.35, 8.3.36, 8.4.27, or 8.5.12 or newer in the same "
    "branch, then restart or redeploy every PHP worker. For vendor packages, "
    "install the vendor's package containing the backported fixes."
)


def parse_version(value: str) -> PhpVersion | None:
    match = VERSION_PATTERN.search(value)
    if not match:
        return None
    return PhpVersion(
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        match.group("suffix"),
    )


def is_prerelease(version: PhpVersion) -> bool:
    """Recognize upstream prereleases without treating distro revisions as prereleases."""
    return bool(re.match(r"(?i)^-?(?:dev|alpha|beta|rc)", version.suffix))


def assess_version(
    version: PhpVersion,
    *,
    target: str,
    source: str,
    remote: bool = False,
    package_revision: str | None = None,
    metadata: dict[str, object] | None = None,
) -> Finding:
    fixed = FIXED_RELEASES.get(version.branch)
    evidence = [Evidence("php_version", str(version), source)]
    if package_revision:
        evidence.append(Evidence("package_revision", package_revision, "OS package database"))
    finding_metadata = dict(metadata or {})

    if version < PhpVersion(5, 4, 0):
        return Finding(
            target=target,
            status=Status.UNKNOWN,
            confidence=Confidence.LOW,
            summary="Unsupported version outside the advisory range",
            detail=(
                "The published affected range begins at PHP 5.4, but this release is "
                "long end-of-life."
            ),
            version=str(version),
            cves=CVES,
            evidence=tuple(evidence),
            remediation=REMEDIATION,
            metadata=finding_metadata,
        )
    same_numeric_release = (
        (
            version.major,
            version.minor,
            version.patch,
        )
        == (fixed.major, fixed.minor, fixed.patch)
        if fixed
        else False
    )
    if fixed and version >= fixed and not (same_numeric_release and is_prerelease(version)):
        return Finding(
            target=target,
            status=Status.PATCHED,
            confidence=Confidence.LOW if remote else Confidence.HIGH,
            summary="Version includes the upstream PHP2Shell fixes",
            detail=f"PHP {version} is at or above the fixed {fixed} release for its branch.",
            version=str(version),
            fixed_version=str(fixed),
            cves=CVES,
            evidence=tuple(evidence),
            metadata=finding_metadata,
        )
    if fixed or version < PhpVersion(8, 2, 0):
        detail = "This version falls within the PHP project's published affected range."
        confidence = Confidence.LOW if remote else Confidence.HIGH
        if package_revision:
            detail += (
                " A distribution package revision was detected; a vendor backport may make the "
                "upstream comparison a false positive, so verify the vendor advisory."
            )
            confidence = Confidence.MEDIUM
        if remote:
            detail += " HTTP version headers may be hidden, forged, cached, or supplied by a proxy."
        return Finding(
            target=target,
            status=Status.AFFECTED,
            confidence=confidence,
            summary="Affected PHP version detected",
            detail=detail,
            version=str(version),
            fixed_version=str(fixed) if fixed else None,
            cves=CVES,
            evidence=tuple(evidence),
            remediation=REMEDIATION,
            metadata=finding_metadata,
        )
    return Finding(
        target=target,
        status=Status.UNKNOWN,
        confidence=Confidence.LOW,
        summary="Version branch is not in the stable-release table",
        detail=(
            "Consult the PHP project or distribution advisory for this prerelease or future branch."
        ),
        version=str(version),
        cves=CVES,
        evidence=tuple(evidence),
        remediation=REMEDIATION,
        metadata=finding_metadata,
    )
