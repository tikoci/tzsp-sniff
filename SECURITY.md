# Security Policy

<!-- From tikoci-github SECURITY.example.md. States read back with the commands in tikoci-github references/settings.md on 2026-11-19; the zizmor and bun audit rows are checked against .github/workflows. Read back again whenever a setting changes. -->

## Reporting a vulnerability

Report privately through
[private vulnerability reporting](https://github.com/tikoci/tzsp-sniff/security/advisories/new).
Do **not** open a public issue for an undisclosed vulnerability. A maintainer
answers in the advisory.

## Scope

tzsp-sniff opens a UDP port and parses whatever datagrams arrive on it, from any sender that can reach the port. It reads no credentials, connects to no device and runs nothing it receives. Parsing untrusted bytes is the main risk: a crash, a hang or excessive memory use on a crafted datagram is a vulnerability here. Vulnerabilities in RouterOS itself go to MikroTik.

## Code scanning

| Check | State |
| --- | --- |
| CodeQL, default setup (`javascript-typescript`, `actions`), Extended suite | enabled |
| zizmor workflow audit, reported to code scanning | enabled |
| Secret scanning with push protection | enabled |
| Private vulnerability reporting | enabled |
| Dependabot alerts and security updates | enabled for GitHub Actions; Bun packages are not supported, so `bun audit` runs on dependency changes, weekly and before each release |
| Dependabot version updates | GitHub Actions and Bun, weekly |
| Dependency review | not enabled: the dependency graph does not read `bun.lock` |
| Code Quality, AI findings | not enabled: paid features |

Open alerts are fixed, or dismissed in the Security tab with a written reason.

An alert in lab or test code (`test/`, and scripts run only by hand) that
flags what the code is for, such as the TZSP lab writing captured traffic to
its evidence files, is dismissed as "used in tests" with a comment saying
what the code does and what guards it (for the lab: only the lab's own
validated datagrams are written). It is a warning, not a waiver: the same
alert in `src/`, a shipped script or a workflow is fixed.

## Supported versions

Fixes go into `main` and the next release. Only the latest release (the npm
`latest` tag) is supported.
