---
name: Bug report
about: Report a problem with the SNIF connector, relay, or CA proxy
title: ''
labels: bug
assignees: ''
---

<!--
SECURITY: Do NOT report vulnerabilities here. See SECURITY.md for private
disclosure (the relay forwarding path, key handling, and certificate issuance
are security-sensitive).
-->

## Description

A clear description of what the bug is.

## Component

- [ ] Connector (`snifd` / `snif-conn`)
- [ ] Relay (`snifd` relay / `snif-relay`)
- [ ] CA proxy (`ca-proxy`)

## To reproduce

Steps to reproduce the behavior:

1.
2.
3.

## Expected behavior

What you expected to happen.

## Environment

- OS / distro:
- OpenSSL version (`openssl version`):
- cURL version (`curl --version` | head -1):
- SNIF version or commit (`git rev-parse --short HEAD`):
- Relay: public `snif.host` / private relay

## Logs

<!-- Relevant output. Enable SNIF_DIAGS in snif.conf for connection diagnostics.
     Redact hostnames/keys as needed. -->

```
```
