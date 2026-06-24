```
/**************************************************************************
 *     _________
 *    /````````_\                  S N I F ~ e2e TLS trust for IoT
 *   /\     , / O\      ___
 *  | |     | \__|_____/  o\       e2e TLS SNI Forwarder
 *  | |     |  ``/`````\___/       e2e TLS CA Proxy
 *  | |     | . | <"""""""~~
 *  |  \___/ ``  \________/        https://snif.host
 *   \  '''  ``` /````````         (C) 2021-2026 VESvault Corp
 *    \_________/                  Jim Zubov <jz@vesvault.com>
 *
 *
 * Apache License, Version 2.0
 * You may use, copy, modify, merge, publish, distribute and/or sell copies
 * of the Software under the terms of the Apache License, Version 2.0, a copy
 * of which is provided in the COPYING file, or http://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.
 *
 **************************************************************************/
```

# SNIF — end-to-end TLS trust for devices behind NAT

[![build](https://github.com/vesvault/snif/actions/workflows/build.yml/badge.svg)](https://github.com/vesvault/snif/actions/workflows/build.yml)
[![codeql](https://github.com/vesvault/snif/actions/workflows/codeql.yml/badge.svg)](https://github.com/vesvault/snif/actions/workflows/codeql.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](COPYING)
[![IETF draft](https://img.shields.io/badge/IETF-draft--zubov--snif-orange.svg)](https://datatracker.ietf.org/doc/draft-zubov-snif/)

**SNIF gives any app on any device a public, browser-trusted HTTPS hostname —
without a public IP, a port forward, or handing your private key to anyone.**

A device generates its own TLS private key, gets a real CA-issued certificate
for a `*.snif.xyz` hostname, and accepts inbound TLS connections relayed
through a public SNIF relay. The relay forwards the raw encrypted TCP stream by
its SNI record — it never holds the private key and cannot read or alter the
traffic. The result is a peer-to-peer, app-level TLS tunnel with no readable
middle-man.


## The problem it solves

IoT devices, home servers, and mobile apps usually sit behind NAT with no
public IP and no stable DNS name. The common workarounds all give up
end-to-end trust:

- **Port forwarding / dynamic DNS** — needs router access and exposes the
  device directly.
- **Reverse-proxy tunnels** — the provider terminates TLS, so it can read and
  modify everything passing through.
- **VPNs** — heavy to provision per-device and still trust a concentrator.

SNIF keeps TLS terminated **on the device**. The relay only sees an opaque,
SNI-routed byte stream, and any misbehavior is publicly detectable through the
CA certificate records.


## How it works

The private key is generated locally by the SNIF connector and never leaves
the device.

The connector sends a CSR to the CA proxy on the SNIF relay. The proxy obtains
an X.509 certificate and returns it to the device.

With the certificate and the private key, the connector can terminate TLS.
Incoming connections to the device's hostname arrive at the relay, which reads
the SNI record to identify the destination device and forwards the TLS TCP
stream through the matching connector.

A device can run `snifd` as a separate connector process that forwards incoming
TLS to local ports — either as plain TCP with `snifd` terminating TLS, or with
TLS terminated by the listening app using the shared certificate and key. In
more advanced setups the connector is integrated directly into the serving app.

From the client's point of view, a TLS connection to a SNIF hostname works
exactly like a connection to any trusted server.

To avoid exposing a unique device hostname through public CA logs, the CA proxy
can issue a wildcard certificate for a subdomain; the actual hostname is then a
specific, unlisted host within that subdomain.

### Initializing the TLS certificate
```
                   DNS: *.snif.xyz
                         |               (no public IP or DNS hostname)
                         v
                    SNIF Relay                     IoT Device
                +----------------+     +--------------------------------+
                |                |     | Generate a Private Key         |
                |                |     | (never leaves the device)      |
Certificate     | snif-cert:     |     |                                |
 Authority      |                <-----< Request a permanent hostname   |
+---------+     |                >-----> host1.snif.xyz                 |
|         |     |                |     |                                |
|     CSR <-----< PKCS#10 CSR    <-----< PKCS#10 CSR for host1.snif.xyz |
|  Verify <-----> host1.snif.xyz |     |                                |
|   Issue >-----> X.509 cert     >-----> X.509 cert for host1.snif.xyz  |
|         |     |                |     |                                |
+---------+     +----------------+     +--------------------------------+
```

### Accepting TLS connections
```
                   DNS: *.snif.xyz
                         |               (no public IP or DNS hostname)
                         v
                    SNIF Relay                     IoT Device
                +----------------+     +--------------------------------+
                |                |     | Private Key +                  |
                |                |     | X.509 cert for host1.snif.xyz  |
                |                |     |   v v v v v                    |
                | snifd relay:   |     | snifd connector or app:        |
                |                |     |                                |
                |                <-----< open ctl connection            |
                | TLS SNI=       |     |                                |
                | host1.snif.xyz >-----> receive ctl notification       |
        +-------> ============== <-----< launch Server Process          |
        |       | e2e TLS tunnel |     |                                |
        |       |                |     |                                |
        |       +----------------+     +--------------------------------+
        |
+-------^------------------+
| https://host1.snif.xyz   |
| (TLS SNI=host1.snif.xyz) |
|                          |
| A web browser, or        |
| any TLS enabled client,  |
| anywhere on the Internet |
+--------------------------+
```


## Quick start — run a connector on a device

```sh
./configure
make
sudo make install
```

Review `/etc/snif/snif.conf` and adjust the port mapping and other variables if
needed. The configuration defaults to the public SNIF relay operated by
VESvault — see https://snif.host for the terms of use.

```sh
# First run prints an authorization link — open it to authorize cert issuance
snif-conn

# Run again once authorized; it prints the SNIF hostname permanently
# assigned to this connector
snif-conn
```

Then enable the daemon (a systemd unit is installed automatically when
`/lib/systemd/system` is available):

```sh
systemctl enable snif-conn
systemctl start snif-conn
```

Point your local TLS services at the SNIF certificate and key —
`/etc/snif/snif.crt` and `/etc/snif/snif.key`. For non-root processes, add the
service uid to the `snif` group to grant access to those files.

Test it: assuming SNIF port 443 maps to the device's HTTPS server, open
`https://{snif_host_name}` from anywhere.


## Embed the connector in an app

To integrate SNIF directly instead of running `snif-conn`:

- Use [`lib/cert.h`](lib/cert.h) to allocate the SNIF hostname, generate the
  private key, and issue and renew the certificate.
- Open a SNIF control connection to `{snif_host_name}` on TCP port `snif`
  (7123).
- Use [`lib/conn.h`](lib/conn.h) to send and receive SNIF messages over the
  control connection and to manage service connections.

The connector libraries build as `libsnif`.


## Run a private SNIF relay

The relay is a standalone deployment (connector + relay `snifd` plus the CA
proxy). It does not need to be embedded in anything else. See
[`ca-proxy/README`](ca-proxy/README) for setup instructions.


## Contents

```
lib/        SNIF connector libraries (libsnif) source
snifd/      SNIF daemon source — relay and connector
ca-proxy/   CA proxy scripts and web API
```


## Requirements

**Connector (`snifd` + `snif-conn`)**
- OpenSSL >= 1.0.1
- cURL

**Private relay (`snifd` + `snif-relay` + `ca-proxy`)**
- HTTP + HTTPS server with `.htaccess` (tested on Apache)
- `mod_rewrite` and `mod_headers` (adjust the `.htaccess` files for other servers)
- PHP + `mod_php`
- Perl + CPAN


## Specification & security

SNIF is a specified open protocol, published as the IETF Internet-Draft
[draft-zubov-snif](https://datatracker.ietf.org/doc/draft-zubov-snif/)
("Deploying Publicly Trusted TLS Servers on IoT Devices Using SNI-based
End-to-End TLS Forwarding"). A snapshot and a plain-language trust model live in
[`doc/`](doc/):

- [doc/security-model.md](doc/security-model.md) — what SNIF protects, the trust
  assumptions, and the threat model.
- [doc/draft-zubov-snif-04.txt](doc/draft-zubov-snif-04.txt) — vendored spec snapshot.

To report a vulnerability, see [SECURITY.md](SECURITY.md) — please disclose
privately, not via public issues.


## License

SNIF is licensed under the **Apache License, Version 2.0** — see [COPYING](COPYING)
and [NOTICE](NOTICE). Both the connector and the relay are permissively licensed:
you can embed the connector in proprietary apps and stand up your own relay
without copyleft obligations.
