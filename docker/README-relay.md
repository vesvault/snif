# Self-hosting a SNIF Relay in Docker

The [SNIF](https://snif.host) relay is the public side of the protocol. It
gives devices behind NAT a publicly trusted HTTPS hostname and forwards the
still-encrypted TLS stream to them by SNI — **it never holds a device private
key and never terminates device TLS**, so it cannot read or alter the traffic
it carries.

The public `snif.xyz` relay exists so the zero-setup path works. Running your
own is how you get hostnames under **your** domain and depend on nobody's
uptime or terms but your own. The whole stack is Apache-2.0.

This image bundles the three pieces of a relay into one container:

- **`snifd` (relay mode)** — forwards public TLS clients to the connector that
  registered the matching SNI name.
- **CA proxy** (Apache + mod_php) — the HTTP API where a device submits a CSR,
  gets authorized, and picks up its certificate.
- **`snif-certd`** (Perl + `Crypt::LE`) — obtains the certificates from Let's
  Encrypt.

> The connector image (`ghcr.io/vesvault/snif`, see [README.md](README.md)) is
> the *device* side. This one is the *relay* side. You run the relay once, on a
> host with a public IP; devices run the connector.


## Prerequisites

Running a relay means running a small public CA proxy, so — unlike the
connector — it needs real infrastructure:

1. **A host with a public IP** (or forwarded ports) reachable from the
   internet.
2. **A domain you control**, with two DNS records pointing at the host — a base
   name for the init origin and a wildcard for device hostnames:

   ```
   snif.example.com        A / AAAA   ->  <relay public IP>
   *.snif.example.com      A / AAAA   ->  <relay public IP>
   ```

   Everything issued becomes `snif-XXXX-YYYY.snif.example.com`.
3. **Open ports** `80` (HTTP-01 ACME challenges + the plaintext cert API),
   `443` (the public relay port), `4443` (the HTTPS init origin), and `7123`
   (where connectors dial in).


## Quick start

```sh
git clone https://github.com/vesvault/snif.git
cd snif
docker build -f Dockerfile.relay -t snif-relay .

docker run -d --name snif-relay \
  -e SNIF_RELAY_DOMAIN=snif.example.com \
  -p 80:80 -p 443:443 -p 4443:4443 -p 7123:7123 \
  -v snif-ca:/var/lib/snif/ca-proxy \
  snif-relay
docker logs -f snif-relay
```

Or with the provided compose file (edit `SNIF_RELAY_DOMAIN` first):

```sh
docker compose -f docker/compose.relay.yaml up -d
```

On first boot the container generates a Let's Encrypt account key, lays out the
CA proxy state on the volume, brings up Apache on `:80` and `:4443`, starts the
issuance daemon, and starts the relay. Point a device at it:

```sh
docker run -d --name dev -v dev-etc:/etc/snif \
  -e SNIF_CONN_INITURL=https://snif.example.com:4443/ \
  -e SNIF_CONN_PORTS='443:web:^80' \
  ghcr.io/vesvault/snif
docker logs -f dev
```

The device prints an authorization link; approve it, and it gets a
`snif-XXXX-YYYY.snif.example.com` certificate issued by **your** relay.


## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SNIF_RELAY_DOMAIN` | *(required)* | Base domain for device hostnames and the init origin |
| `SNIF_RELAY_PORTS` | `443` | Space-separated public TLS ports the relay accepts clients on |
| `SNIF_INIT_PORT` | `4443` | HTTPS init / authorization origin port (the `snifd -a` target) |
| `SNIF_RELAY_ABUSE` | `64` | DoS abuse-detection sensitivity (`snifd -t`) |
| `SNIF_RELAY_MAP` | *(none)* | Static SNI map entries (`snifd -m`), space-separated |
| `SNIF_INIT_CERT` / `SNIF_INIT_KEY` | *(self-signed)* | Publicly trusted cert + key for the init origin |
| `SNIF_LE_STAGING` | `0` | `1` = issue against Let's Encrypt **staging** (untrusted, high rate limits) |

State lives on the `/var/lib/snif/ca-proxy` volume: the account key, issued
certificates, per-device configs, and the control FIFO. Back it up to preserve
the relay's identity and its issued certs. Image upgrades reseed only the code
(web roots + daemons), never the state.


## The init-origin certificate

Device connectors reach the init origin over HTTPS
(`https://snif.example.com:4443/`) and, being ordinary TLS clients, **verify
its certificate**. In production give the relay a publicly trusted cert for
`SNIF_RELAY_DOMAIN`:

```sh
docker run ... \
  -e SNIF_INIT_CERT=/certs/fullchain.pem \
  -e SNIF_INIT_KEY=/certs/privkey.pem \
  -v /path/to/certs:/certs:ro \
  ...
```

Any cert for that name works — a certbot run on the host, or one the relay
issues to itself through its own CA proxy. If you supply nothing, the container
generates a **self-signed** cert so the stack comes up, but device connectors
will refuse it until you provide a trusted one. (The in-browser WebAssembly
demo path uses the browser's trust store the same way.)


## Let's Encrypt staging

While you shake out DNS and ports, set `SNIF_LE_STAGING=1` to issue against the
Let's Encrypt staging environment: certificates are **not** publicly trusted,
but the rate limits are generous, so a misconfiguration won't burn your
production quota. Flip it off (the default) once a staging cert issues cleanly.


## How it fits together

```
  public TLS client ──:443──▶  snifd (relay)  ──SNI──▶  connector on the device
                                    │                     (holds the key,
  device CSR / auth  ──:80/:4443─▶ Apache CA proxy         terminates TLS)
                                    │
                                    ▼
                              snif-certd ──▶ Let's Encrypt
```

The relay and the CA proxy share one state directory; the relay forwards
ciphertext by SNI while the CA proxy handles issuance. Neither ever sees a
device's private key or its plaintext.


## Wildcard certificates via DNS-01 (advanced)

The default HTTP-01 path issues a **single-name** cert for each device hostname
and needs port `80` reachable. If you instead want each device to get a
**wildcard** cert — `*.snif-XXXX-YYYY.snif.example.com`, so it can serve any
sub-name under its allocated host — the CA proxy switches to **DNS-01**. This
needs no inbound `:80`, but it does need a nameserver that accepts authenticated
dynamic updates (RFC 2136 + TSIG).

**It turns on automatically** the moment a TSIG key file named
`etc/<base>.tsig` exists in the CA proxy state (where `<base>` is your
`SNIF_RELAY_DOMAIN`). With it present, hostname allocation returns a `*.`
wildcard CN and `snif-certd` logs `mode=dns`.

### How SNIF validates without a record per device

`snif-certd` writes every device's ACME challenge to **one shared TXT record**,
`snif-pool.<base>`, via a TSIG dynamic update sent to **`ns.<base>`**. A wildcard
CNAME funnels each device's `_acme-challenge` name to that shared record:

```
_acme-challenge.snif-XXXX-YYYY.snif.example.com
        │  (matched by the wildcard CNAME below — RFC 4592 synthesizes it
        │   even though it is two labels below the apex)
        ▼
snif-pool.snif.example.com   TXT  "<token certd just published via TSIG>"
```

So one dynamic, TSIG-writable `snif-pool` record serves unlimited devices.

### DNS records

On the zone for `<base>` (e.g. `snif.example.com`), pointing at the relay host
`RELAY_IP`:

| Name | Type | Value | Purpose |
|---|---|---|---|
| `ns.<base>` | `A`/`AAAA` | your nameserver IP | where certd sends the TSIG update |
| `snif-pool.<base>` | `A`/`AAAA` | `RELAY_IP` | shared record; where devices resolve |
| `*.<base>` | `CNAME` | `snif-pool.<base>.` | funnels device names **and** their `_acme-challenge` to the pool |

`ns.<base>`, `snif-pool.<base>`, and the zone apex are explicit nodes, so they
override the wildcard for their own names.

### BIND example

Zone file (`snif.example.com`):

```
ns          IN  A      RELAY_IP
snif-pool   IN  A      RELAY_IP
snif-pool   IN  AAAA   RELAY_V6
*           IN  CNAME  snif-pool.snif.example.com.
```

Generate a key and grant it rights to just the shared TXT record:

```sh
tsig-keygen -a hmac-sha256 snif-update > /etc/bind/snif-update.key
```

```
# named.conf
include "/etc/bind/snif-update.key";

zone "snif.example.com" {
    type master;
    file "/var/lib/bind/db.snif.example.com";   # dynamic: bind-writable path
    update-policy { grant snif-update name snif-pool.snif.example.com. TXT; };
};
```

Any RFC 2136 + TSIG server works (Knot, PowerDNS, …); the update-policy /
allow-update syntax is what changes.

### Give the CA proxy the key

Drop the **same** key file onto the relay's volume as `etc/<base>.tsig` — the
key name inside must match the `update-policy` grant. `snif-certd` reads it with
`Net::DNS` (the `tsig-keygen` format is accepted as-is):

```sh
docker cp snif-update.key snif-relay:/var/lib/snif/ca-proxy/etc/snif.example.com.tsig
docker exec snif-relay chown snif:snif /var/lib/snif/ca-proxy/etc/snif.example.com.tsig
```

(Or bind-mount it there.) The container reaches `ns.<base>:53` outbound to
perform the update; no inbound port is needed for validation.

See [`ca-proxy/README`](../ca-proxy/README) for the underlying scripts and the
optional APNS wake-up daemon for sleeping iOS devices.


## Notes and limits

- **One container, three daemons.** The relay, Apache, and `snif-certd` share a
  state directory and run together; if any exits, the container stops so your
  orchestrator restarts a clean stack. Splitting them into separate services is
  a reasonable future refinement.
- **`snifd` binds `:443`** as root inside the container (Docker's default
  capability set includes `NET_BIND_SERVICE`); it holds no keys. Run it under a
  dedicated user with a file capability if you want stricter least-privilege.
- **Interactive authorization** for device certs is handled by the same VES /
  Turnstile flow as the public relay; configure `etc/turnstile.*` on the volume
  to gate issuance with a CAPTCHA. See [`ca-proxy/README`](../ca-proxy/README).
- Full trust model: [security-model.md](../security-model.md). Report issues
  via [SECURITY.md](../SECURITY.md).
