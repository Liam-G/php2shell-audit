from php2shell_audit.advisory import FIXED_RELEASES, assess_version, is_prerelease, parse_version
from php2shell_audit.models import Confidence, PhpVersion, Status


def test_parse_distribution_and_header_versions() -> None:
    assert parse_version("PHP 8.4.26 (cli)") == PhpVersion(8, 4, 26)
    assert parse_version("PHP/8.5.12") == PhpVersion(8, 5, 12)
    assert parse_version("8.2.34-1ubuntu2") == PhpVersion(8, 2, 34, "-1ubuntu2")
    assert parse_version("PHP 8.5.12RC1") == PhpVersion(8, 5, 12, "RC1")
    assert parse_version("not a version") is None


def test_prerelease_is_not_treated_as_fixed_release() -> None:
    candidate = PhpVersion(8, 5, 12, "RC1")
    assert is_prerelease(candidate)
    assert not is_prerelease(PhpVersion(8, 5, 12, "-1ubuntu1"))
    assert assess_version(candidate, target="x", source="test").status is Status.AFFECTED


def test_every_supported_branch_boundary() -> None:
    for branch, fixed in FIXED_RELEASES.items():
        prior = PhpVersion(*branch, fixed.patch - 1)
        assert assess_version(prior, target="x", source="test").status is Status.AFFECTED
        assert assess_version(fixed, target="x", source="test").status is Status.PATCHED


def test_old_future_and_vendor_package_classification() -> None:
    old = assess_version(PhpVersion(7, 4, 33), target="x", source="test")
    assert old.status is Status.AFFECTED
    vendor = assess_version(
        PhpVersion(8, 2, 34), target="x", source="test", package_revision="php 8.2.34-9"
    )
    assert vendor.status is Status.AFFECTED
    assert vendor.confidence is Confidence.MEDIUM
    assert "backport" in vendor.detail
    future = assess_version(PhpVersion(8, 6, 0), target="x", source="test")
    assert future.status is Status.UNKNOWN


def test_remote_evidence_is_low_confidence() -> None:
    result = assess_version(
        PhpVersion(8, 5, 11), target="https://example.test/", source="header", remote=True
    )
    assert result.status is Status.AFFECTED
    assert result.confidence is Confidence.LOW
