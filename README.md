# php2shell-audit

`php2shell-audit` is a non-destructive exposure scanner for the two critical
PHP-core vulnerabilities disclosed on 21 October 2026:

- CVE-2026-109618 — remote code execution through out-of-memory corruption;
- CVE-2026-109619 — remote code execution through stale global state.

It inventories local PHP runtimes, records package provenance and relevant
configuration, or passively fingerprints authorized web targets. It produces
reproducible text, JSON, and SARIF 2.1.0 reports for operators and CI.

> [!CAUTION]
> Remote mode is only for systems you own or have explicit permission to test.
> It sends one ordinary `HEAD` request per target and never sends malformed
> multipart data, exhausts memory, crashes workers, or attempts code execution.

## Capabilities

- discovers versioned and unversioned PHP binaries across `PATH` and common locations;
- executes a small read-only PHP expression to collect the exact runtime version, SAPI,
  loaded `php.ini`, and relevant temporary-mitigation settings;
- records Debian, RPM, or Alpine package provenance when available;
- compares PHP 8.2–8.5 against the official fixed-release boundaries;
- identifies PHP 5.4–8.1 as affected/EOL while warning about possible vendor backports;
- keeps **affected version**, **patched**, **unknown**, and **operational error** distinct;
- passively reads `X-Powered-By` and `Server` headers with same-origin redirects only;
- scans target lists concurrently with bounded workers, timeout, and target-count limits;
- requires an explicit authorization acknowledgement before network traffic;
- supports a no-traffic dry run and offline single-version assessment;
- emits human-readable text, stable JSON, and GitHub-compatible SARIF 2.1.0;
- has no runtime dependencies beyond Python 3.10 or newer.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install .
php2shell-audit --version
```

From a source checkout, `./phpscanner.py` is also available as a convenience launcher.

## Local inventory

Discover and inspect local PHP installations:

```bash
php2shell-audit local
```

Inspect explicit binaries and write JSON:

```bash
php2shell-audit local \
  --php-bin /usr/bin/php8.2 \
  --php-bin /opt/php/8.4/bin/php \
  --format json --output report.json
```

The configuration observations are not treated as fixes. PHP states that an
updated runtime is the only complete mitigation. After updating, restart or
redeploy every FPM, Apache, CGI, FrankenPHP, or LiteSpeed worker.

## Authorized remote fingerprinting

Preview a target list without sending traffic:

```bash
php2shell-audit remote --target-file targets.txt --dry-run
```

Send one bounded `HEAD` request to each authorized target:

```bash
php2shell-audit remote \
  --target https://staging.example.test \
  --workers 4 --timeout 5 \
  --acknowledge-authorization I_HAVE_AUTHORIZATION
```

Generate SARIF for GitHub code scanning:

```bash
php2shell-audit remote \
  --target-file authorized-targets.txt \
  --format sarif --output php2shell.sarif \
  --acknowledge-authorization I_HAVE_AUTHORIZATION
```

Remote output is intentionally low-confidence. Headers may be absent, forged,
cached, or inserted by a proxy, and vendors can backport fixes without changing
the upstream-looking version. An `UNKNOWN` result is not a clean bill of health.

## Offline version checks

```bash
php2shell-audit version 8.4.26
php2shell-audit version 8.4.27 --format json
```

## Fixed upstream releases

| Branch | First fixed release |
|---|---:|
| PHP 8.2 | 8.2.35 |
| PHP 8.3 | 8.3.36 |
| PHP 8.4 | 8.4.27 |
| PHP 8.5 | 8.5.12 |

PHP 8.1 and older are end-of-life upstream. Some distribution or LTS vendors
may ship backports, which must be confirmed against that vendor's advisory.

## Exit codes

The convention matches `jwt-audit`, `oidc-audit`, and `noirspect`:

| Code | Meaning |
|---:|---|
| `0` | No affected version was detected and no operational error occurred. |
| `1` | Invalid input or an operational error prevented a complete check. |
| `2` | One or more affected versions were detected. |

`UNKNOWN` alone exits `0` because it is not a confirmed finding. Consumers
must still inspect the structured summary and should not interpret unknown as patched.

## Development

```bash
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
mypy src
pytest
python -m build
```

Tests use subprocess and HTTP fakes and never contact external targets.

## Evidence model and limitations

This is a version and provenance scanner, not an exploit verifier. Even a local
version comparison cannot prove exploitability because downstream vendors and
private builds may backport patches. Conversely, failure to observe a remote
PHP header proves nothing. See [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

Sources: [PHP security announcement](https://www.php.net/),
[CVE-2026-109618 advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
and [CVE-2026-109619 advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

## Project

Created and maintained by [Liam Giannini](https://github.com/Liam-G) of
[Webcracy.ch](https://webcracy.ch). Licensed under the MIT License.
