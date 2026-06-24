# Security Policy

SNIF terminates TLS on the device and relays the resulting end-to-end
encrypted byte stream through a public relay that **cannot read or modify**
the traffic. Because SNIF is trust-bearing infrastructure, we take security
reports seriously and aim to handle them transparently.

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Report privately through either channel:

- GitHub's [private vulnerability reporting](https://github.com/vesvault/snif/security/advisories/new)
  (Security → Advisories → "Report a vulnerability"), or
- Email **security@vesvault.com**. If you wish to encrypt the report, request
  our PGP key at that address first.

Please include:

- the affected component (connector `snifd`/`snif-conn`, relay, or CA proxy),
- the version or commit (`git rev-parse HEAD`),
- a description, impact assessment, and reproduction steps or PoC,
- any suggested remediation.

## What to expect

- **Acknowledgement** within 3 business days.
- An initial **assessment** (severity, affected versions) within 10 business days.
- We will keep you updated on remediation progress and coordinate a disclosure
  timeline with you. We aim to ship a fix and publish an advisory within 90 days
  of the report; we will tell you if we expect to need longer.
- With your consent, we will credit you in the advisory.

We support coordinated disclosure and will not pursue legal action against
good-faith research that respects user privacy, avoids service disruption, and
gives us reasonable time to remediate before public disclosure.

## Scope

In scope:

- the SNIF connector (`lib/`, `snifd/`, `bin/snif-conn`),
- the SNIF relay (`snifd` relay mode, `bin/snif-relay`),
- the SNIF CA proxy (`ca-proxy/`),
- the protocol itself (see [`doc/`](doc/) and
  [draft-zubov-snif](https://datatracker.ietf.org/doc/draft-zubov-snif/)) —
  protocol-level weaknesses are in scope even if no implementation bug exists.

Out of scope:

- the operation of the public relay service at `snif.host` (report those to
  the same address, but they are handled as an operational matter, not a code
  advisory),
- vulnerabilities in third-party dependencies (OpenSSL, cURL) — report those
  upstream; tell us if SNIF's usage amplifies the impact.

## Supported versions

SNIF is pre-1.0 and ships from `master`. Security fixes are applied to the
latest release and to `master`. Please verify a report against the current
`master` before submitting.

## Trust model

The security claims SNIF makes — what the relay can and cannot do, key
custody, and the threat model — are documented in
[`doc/security-model.md`](doc/security-model.md) and Section 5 of the
[Internet-Draft](doc/draft-zubov-snif-04.txt). Reports that challenge those
claims are especially welcome.
