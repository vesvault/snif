# SNIF security model

This document states precisely what SNIF protects, what it does **not**, and
the trust assumptions behind the claim that *"the relay cannot read or alter
your traffic."* It summarizes Section 5 (Security Considerations) of the
[Internet-Draft](https://datatracker.ietf.org/doc/draft-zubov-snif/); the draft is normative where the two
disagree.

## Roles

- **Connector** — runs on the device, generates and holds the private key,
  terminates TLS.
- **Relay** — a public rendezvous point. Forwards TLS byte streams by their SNI
  record. Untrusted with plaintext.
- **CA proxy** — obtains a publicly trusted X.509 certificate for the
  connector's hostname.
- **Client** — any TLS client that sends SNI (e.g. a browser).

## What SNIF guarantees

1. **The private key never leaves the device.** It is generated locally by the
   connector and is never transmitted to the relay, the CA proxy, or any other
   party.
2. **The relay cannot read the traffic.** Service traffic between client and
   connector is end-to-end TLS terminated by the device. The relay has no key
   material and forwards opaque ciphertext routed only by the SNI record.
3. **The relay cannot silently impersonate the device.** It cannot produce a
   certificate matching the device's private key. Any certificate mis-issued
   for the device's hostname appears in public **Certificate Transparency**
   logs, making relay or CA misbehavior **publicly detectable**.
4. **Tampering fails closed.** If an attacker alters the CN allocation, the CSR
   submission, or the certificate download responses, the connector ends up
   without a certificate that matches its key and must hard-reset — it does not
   proceed in a silently compromised state. A connector SHOULD NOT reveal its
   hostname until it has downloaded and validated its certificate.

## Trust assumptions

- The **CA** behind the CA proxy issues certificates correctly, and CT logs are
  monitored. SNIF's detectability guarantee rests on CT, not on trusting the
  relay.
- The **client** validates the server certificate as it would for any HTTPS
  endpoint. SNIF provides a publicly trusted certificate precisely so existing
  clients need no special trust configuration.
- For **high-security deployments**, the connector is configured with an HTTPS
  `apiUrl` and the relay presents a trusted client certificate on the control
  connection; if the connector cannot validate the relay's client certificate
  it MUST NOT send sensitive information and MUST NOT trust messages from the
  relay.

## Channel-by-channel

| Channel | Transport | Sensitive? | Notes |
|---|---|---|---|
| CA proxy requests (CSR submit, cert download) | plain HTTP acceptable | No | CSR and issued cert are public information anyway; tampering only forces a hard reset |
| Control connection | TLS, connector-supplied cert | Yes | Sensitive SNIF messages; client-cert from relay recommended in high-security mode |
| Service connection | cleartext TCP | Low | Carries a single-use random `conn_id`; usable once, only by the targeted connector |
| Client ⇄ connector | end-to-end TLS | — | Real payload; security is that of the app protocol on top |

## Hostname privacy

Every issued certificate is permanently visible in CT logs. To avoid exposing a
unique device hostname there, the CA proxy SHOULD issue **wildcard**
certificates; the actual connector hostname is then a specific, unlisted host
within that wildcard subdomain.

## Abuse and denial of service

- Certificate issuance SHOULD require authorization — interactive (the connector
  opens an `authUrl` in a browser) or, for headless devices, a non-interactive
  setup-URL mechanism that MUST alert the user on misrouted setup so a hijacked
  setup URL is detected and the device re-initialized.
- The relay implements abuse management (draft §4.6) to mitigate flooding.

## Out of scope / residual risks

SNIF is a transport-trust layer. The following are explicitly **not** solved by
SNIF and remain the responsibility of the application or operator:

- **End-application authentication.** SNIF authenticates the *server hostname*
  to the client. Authenticating *users* to the application is the app
  protocol's job.
- **Traffic analysis by the relay.** The relay cannot read content, but it does
  observe connection metadata — which hostnames are active, timing, and byte
  volumes. SNIF does not hide this.
- **Relay availability.** A relay can refuse or drop connections (denial of
  service). It cannot, however, compromise confidentiality or integrity by
  doing so.
- **Device and key compromise.** SNIF assumes the device protects its own
  private key; physical or host compromise is out of scope.
- **Dependency security.** Soundness depends on the underlying TLS stack
  (OpenSSL) and cURL.

## Reporting

Security reports: see [`../SECURITY.md`](../SECURITY.md). Reports that challenge
any guarantee above are especially welcome.
