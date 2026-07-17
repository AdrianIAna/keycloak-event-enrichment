# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.1.x   | ✅ |
| 1.0.x   | ❌ (upgrade to 1.1.x) |

Each release is built and tested against the Keycloak versions listed in the
README compatibility table.

## Reporting a Vulnerability

Please don't open a public issue for security problems. Report privately via
[GitHub Security Advisories](../../security/advisories/new) ("Report a
vulnerability" on the repository's Security tab).

You can expect an acknowledgement within a few days. Once a fix is available,
the advisory gets published together with a patched release.

## Design notes

- Enrichment is fail-open by design: if a GeoIP lookup or User-Agent parse
  fails, the event is stored without enrichment. A broken MMDB file can never
  block event persistence or authentication.
- User-Agent strings are truncated before parsing (`max-ua-length`, default
  512) as a ReDoS guard.
- The extension only reads the client IP and User-Agent header that Keycloak
  already has; it adds no new inputs and exposes no endpoints.
