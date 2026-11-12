<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# Security policy

## Supported versions

Until 1.0, only the latest minor release line receives security fixes.
Fixes land on `main` and ship in a patch release.

| Version | Supported |
|---|---|
| latest 0.x release | Yes |
| `main` (unreleased) | Yes |

## Reporting a vulnerability

Please **do not** open a public issue. Report it privately through GitHub:
[Security → Report a vulnerability](https://github.com/brunopacheco1/portitor/security/advisories/new).

Include what is affected, how to reproduce it, and the impact you see.
What to expect:
- an acknowledgement within 7 days;
- a fix released within 60 days for vulnerabilities of medium severity or
  higher, sooner for critical ones;
- a disclosure date agreed with you, a GitHub security advisory (with a CVE
  when it applies), and credit in the advisory unless you prefer otherwise.

## Scope

Of particular interest: parsing of DSP and DCP messages, token and
signature verification (`crates/portitor-dcp`), DID resolution, and anything
that lets a remote party read data or bypass a policy. The threat model is
in the [security assurance case](docs/SECURITY-ASSURANCE.md).

## Verifying a release

Each release image is signed with cosign (keyless) and carries an SBOM and
build provenance. [docs/RELEASING.md](docs/RELEASING.md) shows how to check them.
