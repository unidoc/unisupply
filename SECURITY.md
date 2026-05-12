# Security Policy

`unisupply` is a security tool. We treat vulnerabilities in this project — and
in the dependencies it bundles — with the same seriousness we expect users to
treat findings it produces against their own code.

## Supported versions

| Version  | Status                                  |
| -------- | --------------------------------------- |
| `0.4.x`  | Supported — current release line        |
| `< 0.4`  | Not supported — no public release exists |

`0.4.0` is the first public release. Once a future minor or major is cut, the
previous line will continue to receive security fixes for one release cycle,
and this table will be updated accordingly — always treat it as authoritative.

## Reporting a vulnerability

**Please do not file public GitHub issues for security problems.** Use one of
the non-public channels below.

### Preferred: email

Send a report to **security@unidoc.io**. Include:

- A description of the issue and its impact.
- Steps to reproduce, ideally with a minimal proof of concept.
- The affected version(s) and platform.
- Any suggested mitigation, if you have one.

PGP-encrypted reports are welcome — request our public key in your first
message and we will respond with it before you send sensitive details.

### Alternative: GitHub Private Vulnerability Reporting

GitHub's native Private Vulnerability Reporting is also accepted:

> Repository → **Security** tab → **Report a vulnerability**

This auto-creates a private security advisory draft that the maintainers can
collaborate on with you, and produces a clean audit trail for CVE assignment.

## Response targets

| Stage                        | Target                              |
| ---------------------------- | ----------------------------------- |
| Acknowledgement of report    | Within **3 business days**          |
| Triage and severity decision | Within **7 business days**          |
| Fix or disposition           | Within **30 days** for High / Critical |
| Public disclosure            | Coordinated with reporter           |

If we cannot meet a target we will say so explicitly in the thread, with a
revised estimate. Silent slips are a bug — please poke us.

## Scope

`unisupply` is shipped as a single self-contained Go binary. The security
scope tracks the **execution surface** of that binary — not just first-party
code — so that reporters do not have to guess which third-party module
boundary we consider "ours".

### In scope

- Vulnerabilities in `unisupply`'s own source code (`cmd/`, `pkg/`,
  `internal/`).
- Vulnerabilities reachable through the `unisupply` execution surface in
  **bundled dependencies** linked into the released binary — e.g.
  `golang.org/x/vuln`, `gopkg.in/yaml.v3`, UniPDF, UniChart, and any other
  module that ends up in `go.sum`.
- Vulnerabilities in CI / release infrastructure that affect the integrity of
  released artifacts (`.github/workflows/`, `.github/allowed_signers`,
  signing flow).
- Vulnerabilities in policy / SBOM / report rendering that lead to incorrect
  security conclusions (e.g. a malformed `go.mod` that causes a real CVE to
  be silently skipped).

### Out of scope

- Vulnerabilities in tools `unisupply` may invoke as **external subprocesses**
  but does not bundle (e.g. `govulncheck`, `gosec` when those are installed
  locally by the user). Report those upstream.
- The GitHub API and other third-party services queried at runtime.
- Social-engineering reports against UniDoc staff or infrastructure not
  related to this repository.
- Findings produced by `unisupply` against arbitrary third-party Go modules —
  those are findings *for* the respective upstream, not against `unisupply`.

This scoping follows NIST SSDF RV.1: vulnerabilities in software and the
dependencies that ship inside it are tracked as a unified surface.

## Disclosure policy

We practice coordinated disclosure:

1. Reporter contacts us via one of the channels above.
2. We acknowledge, triage, and agree on a remediation timeline.
3. We prepare a fix in a private branch / advisory.
4. A CVE is requested where applicable (via GitHub or directly via MITRE).
5. The fix is released; the advisory is published; the reporter is credited
   unless they prefer otherwise.

We do not require reporters to sign an NDA, and we will not pursue legal
action against good-faith security research conducted within the scope above.
