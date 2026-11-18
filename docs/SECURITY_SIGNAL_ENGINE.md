# Deterministic Security Signal Engine

The first rule-based security intelligence layer consumes only persisted worker
observations. It performs no network requests and does not create confirmed
findings.

## Signals

- Version-bearing Server, X-Powered-By, X-AspNet-Version, and X-Generator headers.
- Wildcard CORS origin observed together with credential allowance on one host.
- Set-Cookie observations missing Secure, HttpOnly, or SameSite attributes.
- Cleartext HTTP URLs.
- Conventional sensitive paths such as /.env, /.git/config, /server-status,
  /debug, and common backup/archive suffixes.

## Trust and evidence rules

Every signal contains source observation IDs, a stable identifier, a rationale,
and validation guidance. Cookie values are never copied into signal output.
Confidence is limited to low or medium. Severity remains `not_assessed`, and
disposition remains `requires_validation`.

A path observation is not proof that a resource exists. A version string is not
proof that software is vulnerable. Header combinations need endpoint-specific
browser validation. Missing headers are never inferred from an incomplete feed.

## Current limitation

This engine is a deterministic triage layer, not the scanner. It does not yet
collect HTTP responses from targets, follow links, crawl APIs, verify exposure,
or invoke the DeepSeek pipeline automatically. The next engineering milestone
is a tightly scoped HTTP collection runtime with DNS/IP and redirect enforcement,
then evidence-producing checks integrated with this signal engine.
