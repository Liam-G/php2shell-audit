import urllib.error
from email.message import Message
from unittest.mock import patch

from php2shell_audit.models import Status
from php2shell_audit.remote import inspect_target, normalize_target, scan_remote


class FakeResponse:
    def __init__(self, powered_by: str | None) -> None:
        self.headers = Message()
        if powered_by:
            self.headers["X-Powered-By"] = powered_by
        self.status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def geturl(self) -> str:
        return "https://example.test/"


class FakeOpener:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response

    def open(self, _request, timeout: float):
        assert timeout == 2
        return self.response


class ErrorOpener:
    def open(self, _request, timeout: float):
        raise urllib.error.URLError("offline")


def test_target_normalization_and_restrictions() -> None:
    assert normalize_target("example.test", allow_http=False) == "https://example.test/"
    try:
        normalize_target("http://example.test", allow_http=False)
    except ValueError as exc:
        assert "HTTPS" in str(exc)
    else:
        raise AssertionError("plain HTTP should be rejected")


@patch("php2shell_audit.remote.urllib.request.build_opener")
def test_remote_header_fingerprint(build_opener) -> None:
    build_opener.return_value = FakeOpener(FakeResponse("PHP/8.4.26"))
    finding = inspect_target("https://example.test", timeout=2, verify_tls=True, allow_http=False)
    assert finding.status is Status.AFFECTED
    assert finding.version == "8.4.26"


@patch("php2shell_audit.remote.urllib.request.build_opener")
def test_missing_header_is_unknown(build_opener) -> None:
    build_opener.return_value = FakeOpener(FakeResponse(None))
    finding = inspect_target("https://example.test", timeout=2, verify_tls=True, allow_http=False)
    assert finding.status is Status.UNKNOWN


@patch("php2shell_audit.remote.urllib.request.build_opener")
def test_network_error_is_reported(build_opener) -> None:
    build_opener.return_value = ErrorOpener()
    finding = inspect_target("https://example.test", timeout=2, verify_tls=True, allow_http=False)
    assert finding.status is Status.ERROR


@patch("php2shell_audit.remote.inspect_target")
def test_remote_scan_deduplicates_and_collects_errors(inspect) -> None:
    from php2shell_audit.models import Confidence, Finding

    inspect.return_value = Finding(
        "https://example.test/", Status.ERROR, Confidence.LOW, "failed", "offline"
    )
    report = scan_remote(
        ["example.test", "example.test"],
        timeout=2,
        workers=1,
        verify_tls=True,
        allow_http=False,
    )
    assert inspect.call_count == 1
    assert len(report.errors) == 1
