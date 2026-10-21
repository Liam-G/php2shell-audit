"""Conservative HTTP-header fingerprinting."""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .advisory import CVES, assess_version, parse_version
from .models import Confidence, Evidence, Finding, ScanReport, Status

PHP_HEADER_PATTERN = re.compile(r"(?i)PHP[/ ]\s*(\d+\.\d+\.\d+(?:[-+~][^\s;,)]+)?)")


class SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(newurl)
        if (old.scheme.lower(), old.hostname, old.port) != (
            new.scheme.lower(),
            new.hostname,
            new.port,
        ):
            raise urllib.error.HTTPError(newurl, code, "cross-origin redirect refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def normalize_target(value: str, *, allow_http: bool) -> str:
    value = value.strip()
    if "://" not in value:
        value = "https://" + value
    parsed = urllib.parse.urlsplit(value)
    schemes = {"https", "http"} if allow_http else {"https"}
    if parsed.scheme not in schemes:
        raise ValueError("targets must use HTTPS (or pass --allow-insecure-http)")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("target must contain a hostname and no URL credentials")
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, "")
    )


def inspect_target(target: str, *, timeout: float, verify_tls: bool, allow_http: bool) -> Finding:
    try:
        normalized = normalize_target(target, allow_http=allow_http)
    except ValueError as exc:
        return Finding(target, Status.ERROR, Confidence.LOW, "Invalid target", str(exc), cves=CVES)
    context = (
        ssl.create_default_context() if verify_tls else ssl._create_unverified_context()  # noqa: S323 - explicit CLI opt-out
    )
    opener = urllib.request.build_opener(
        SameOriginRedirectHandler(), urllib.request.HTTPSHandler(context=context)
    )
    request = urllib.request.Request(
        normalized,
        method="HEAD",
        headers={"User-Agent": "php2shell-audit/0.1 (+safe-header-check)"},
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            headers = response.headers
            final_url = response.geturl()
            status_code = response.status
    except urllib.error.HTTPError as exc:
        headers = exc.headers
        final_url = exc.geturl()
        status_code = exc.code
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return Finding(
            normalized, Status.ERROR, Confidence.LOW, "HTTP inspection failed", str(exc), cves=CVES
        )
    values = [value for name in ("X-Powered-By", "Server") for value in headers.get_all(name, [])]
    evidence_text = " | ".join(values)
    match = PHP_HEADER_PATTERN.search(evidence_text)
    metadata = {"http_status": status_code, "final_url": final_url}
    if not match:
        evidence = tuple(Evidence("http_header", value, normalized) for value in values)
        return Finding(
            normalized,
            Status.UNKNOWN,
            Confidence.LOW,
            "PHP version not disclosed",
            "No precise PHP version appeared in X-Powered-By or Server headers. "
            "This is not evidence that the target is safe.",
            cves=CVES,
            evidence=evidence,
            metadata=metadata,
        )
    version = parse_version(match.group(1))
    if not version:
        return Finding(
            normalized,
            Status.UNKNOWN,
            Confidence.LOW,
            "PHP version was not recognized",
            match.group(1),
            cves=CVES,
            metadata=metadata,
        )
    return assess_version(
        version, target=normalized, source="HTTP response header", remote=True, metadata=metadata
    )


def scan_remote(
    targets: list[str], *, timeout: float, workers: int, verify_tls: bool, allow_http: bool
) -> ScanReport:
    unique = list(dict.fromkeys(targets))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        findings = tuple(
            executor.map(
                lambda item: inspect_target(
                    item, timeout=timeout, verify_tls=verify_tls, allow_http=allow_http
                ),
                unique,
            )
        )
    errors = tuple(
        f"{item.target}: {item.detail}" for item in findings if item.status is Status.ERROR
    )
    notes = (
        "Remote mode sends one ordinary HEAD request per target and never attempts exploitation.",
        "Remote fingerprints have low confidence; use local/package inventory for authority.",
    )
    return ScanReport("remote", findings, errors, notes)
