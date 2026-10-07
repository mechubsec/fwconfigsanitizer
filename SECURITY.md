# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security vulnerability.

Instead, use GitHub's private vulnerability reporting for this repository:

https://github.com/mechubsec/fwconfigsanitizer/security/advisories/new

Include what you'd include in a bug report — affected version (see the `VERSION` file, or the commit SHA), reproduction steps, and impact — but keep it in the private report, not a public issue, PR, or discussion.

## Scope

This is a client-side, browser-based tool whose entire purpose is to keep firewall configuration data on the user's machine and strip identifying/sensitive data from it before it's shared. Vulnerability classes we especially want to hear about:

- **Any code path that sends data off the browser** — a network call of any kind (`fetch`, `XMLHttpRequest`, `WebSocket`, a form submission, a redirect through an external domain, a CDN-hosted asset, etc.) would break the tool's core privacy guarantee and is treated as a critical finding regardless of intent.
- **XSS or script injection** via a pasted/uploaded config — since the tool renders and diffs arbitrary user-supplied text, anything that lets attacker-controlled config content execute as script in the page is in scope.
- **Sanitization logic that silently fails to redact what it claims to** — a category that's supposed to strip sensitive data (IPs, keys, hashes, hostnames, etc.) but leaves it in the sanitized output is a real-world data-leak risk for anyone who trusts the tool's output, even though it's "just" a bug.
- **Anything that causes the mapping file or a saved preset to expose more than the user intended** (e.g. via `localStorage`, a downloaded file, or the Restore flow).

## Response

This is a community-maintained project. There's no guaranteed SLA. A human maintainer is responsible for triaging every report and for all disclosure and fix decisions.
