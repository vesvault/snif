# SNIF documentation

- **[security-model.md](security-model.md)** — what SNIF protects, the trust
  assumptions, and the threat model. Start here if you are evaluating SNIF for
  security-sensitive use.
- **[draft-zubov-snif-04.txt](draft-zubov-snif-04.txt)** — vendored snapshot of
  the SNIF protocol specification (IETF Internet-Draft).

## The protocol specification

SNIF is a specified open protocol, not just an implementation. The
specification is published as an IETF Internet-Draft:

> **Deploying Publicly Trusted TLS Servers on IoT Devices Using SNI-based
> End-to-End TLS Forwarding (SNIF)** — J. Zubov, VESvault Corp.
> Intended status: Experimental.

| Resource | Link |
|---|---|
| Canonical draft (always current) | https://datatracker.ietf.org/doc/draft-zubov-snif/ |
| Internet-Draft source repo | https://github.com/vesvault/snif-i-d |
| Relay protocol suite overview | https://snif.host/relay-proto |
| Project site | https://snif.host |

The snapshot in this directory is for offline reference and may lag the
canonical draft. The draft defines the **CA Proxy protocol** (§3), the **Relay
protocol suite** (§4 — control, service, client, and IPC FIFO connection
protocols, plus abuse management), and the **Security Considerations** (§5)
summarized in [security-model.md](security-model.md).
