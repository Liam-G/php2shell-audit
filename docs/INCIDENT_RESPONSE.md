# PHP2Shell incident-response guide

`php2shell-audit hunt` identifies evidence worth triaging. It does not declare a
host compromised and it cannot prove that a host is clean.

## Collected indicators

| Rule | Evidence | Confidence |
|---|---|---:|
| `PHP2SHELL-IOC-001` | `PHP_SESSION_UPLOAD_PROGRESS` in a request/audit record | medium |
| `PHP2SHELL-IOC-002` | a multipart `PHPSESSID` form field | medium |
| `PHP2SHELL-IOC-003` | PHP memory exhaustion | low |
| `PHP2SHELL-IOC-004` | worker crash, signal 11, or heap corruption | medium |
| `PHP2SHELL-IOC-005` | ASAN/use-after-free diagnostic | high |
| `PHP2SHELL-IOC-006` | shell/network tool directly spawned by a web worker | medium |

The first two patterns are most useful in WAF or request-body audit logs; normal
access logs often omit form fields. OOM and worker crashes have many benign
causes. Process lineage is only a snapshot and can miss short-lived processes.

## Triage sequence

1. Preserve the complete source logs and record their hashes and timestamps.
2. Correlate matching lines with the same client, request ID, worker, container,
   virtual host, and five-minute time window.
3. Review PHP-FPM, Apache, LiteSpeed, FrankenPHP, system, kernel, WAF, and proxy
   logs for OOM, signal 11, heap corruption, restarts, or unusual child processes.
4. Inspect the affected worker/container for unexpected files, scheduled tasks,
   changed startup configuration, new accounts/keys, and outbound connections.
5. If compromise is plausible, isolate the instance, preserve volatile evidence,
   rotate credentials reachable by the web-worker account, rebuild from trusted
   artifacts, and patch PHP before restoring service.
6. Do not run public exploit code against production to “confirm” the finding.

## Research basis

The defensive patterns were informed by the official PHP advisories and public
research from [ikow](https://github.com/ikow/php2shell-poc),
[eness](https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC),
and [Zer061](https://github.com/Zer061/CVE-2026-109618). Those repositories
contain active triggers and exploit research; this project imports none of them.
