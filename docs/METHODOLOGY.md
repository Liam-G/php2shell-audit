# Methodology

## What the scanner establishes

Local mode executes the selected PHP interpreter and records `PHP_VERSION`,
`PHP_SAPI`, `PHP_BINARY`, the loaded configuration path, request-size limits,
input limits, session upload-progress settings, session serializer settings,
and settings mentioned in upstream temporary mitigation guidance. It then looks
up the owning OS package where the host package manager supports that operation.
These are CLI-SAPI values and are labeled accordingly; web SAPIs may override them.

Remote mode performs passive fingerprinting only. It sends a `HEAD` request,
follows redirects only on the same origin, and checks `X-Powered-By` and
`Server` for a complete PHP version. It does not infer a PHP version from a CMS,
framework, cookie, file extension, or error-page appearance.

## Classification

- `affected`: the observed version is in the published affected range;
- `patched`: the version is at or above the upstream fixed release in PHP
  8.2, 8.3, 8.4, or 8.5;
- `unknown`: evidence is absent or outside the published stable-release table;
- `error`: input or an operational failure prevented assessment.

Confidence describes the evidence, not severity. Local upstream builds receive
high confidence. OS packages receive medium confidence when the upstream number
appears affected because a backport may exist. HTTP evidence is always low confidence.

## Deliberate exclusions

The scanner does not attempt to produce an out-of-memory condition, manipulate
session upload progress, arrange heap contents, crash a worker, disclose memory,
or execute code. Such behavior would be unsafe for an inventory tool and could
not reliably prove absence of the vulnerabilities.

Public PoCs show that build-specific assumptions can turn an attempted check
into a worker crash. For that reason the remote mode remains header-only. The
`hunt` mode instead consumes existing logs and a point-in-time process tree. It
hashes matching log lines rather than copying potentially sensitive request
bodies into reports. Its indicators are deliberately broad and require human
correlation; absence of an indicator does not prove that exploitation did not occur.
