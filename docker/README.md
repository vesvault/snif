# SNIF Connector in Docker

Run a [SNIF](https://snif.host) connector as a container: any service in your
stack gets a public, browser-trusted `https://` hostname — no public IP, no
port forwarding, no reverse proxy that can read your traffic. The TLS private
key is generated inside the container and never leaves the Docker volume; the
SNIF relay forwards the encrypted stream by its TLS SNI record and cannot
decrypt it.

The connector makes **outbound connections only** (to the SNIF relay). Do not
publish any ports — no `-p` flags, no `ports:` section, no router setup.


## Quick start

```sh
docker run -d --name snif -v snif-etc:/etc/snif ghcr.io/vesvault/snif
docker logs -f snif
```

1. The log prints an **authorization link**. Open it in any browser — your
   phone works, nothing needs to run on the Docker host — and complete the
   verification. The link is re-printed every 30 seconds until authorized.
2. Once authorized, the log prints the permanent **SNIF hostname** assigned to
   this connector.
3. Verify: open `https://{snif_hostname}:7357/` from anywhere — the built-in
   test responder answers over browser-trusted TLS.

The hostname is also written to `/etc/snif/hostname` on the volume:

```sh
docker exec snif cat /etc/snif/hostname
```

The default configuration uses the public SNIF relay operated by VESvault —
see https://snif.host for the terms of use.


## Identity and persistence

The private key, the certificate, and therefore the hostname live on the
`/etc/snif` volume:

- Restarts and image upgrades keep the same hostname; the certificate renews
  automatically. Authorization happens **once per volume**.
- Deleting the volume means a new key, a new authorization, and a new
  hostname.
- Back up the volume to preserve the identity; anyone holding `snif.key` can
  serve TLS for your SNIF hostname.


## Configuration

All variables are optional and match the `snif.conf` names used by the
non-container connector:

| Variable | Default | Purpose |
|---|---|---|
| `SNIF_CONN_PORTS` | `7357:^` | Port mappings, space separated — see below |
| `SNIF_CONN_INITURL` | `https://snif.snif.xyz:4443/` | Relay initialization URL; point at your own relay to self-host |
| `SNIF_CONN_APIURL` | *(relay default)* | CA proxy API URL, only if required by the relay |
| `SNIF_CONN_HOSTNAME` | *(auto-allocated)* | Explicit hostname; MUST match an issued wildcard certificate |
| `SNIF_CONN_DIR` | `/etc/snif` | Key/cert directory (the volume) |
| `SNIF_INIT_RETRY` | `30` | Seconds between initialization retries |

### Port mappings

Each `SNIF_CONN_PORTS` entry maps a port of the public SNIF hostname to a
destination reachable from the container:

| Entry | Meaning |
|---|---|
| `rem_port:host:port` | TLS passes through to `host:port`; the destination terminates TLS itself using the shared `snif.crt` + `snif.key` (end-to-end) |
| `rem_port:host:^port` | The connector terminates TLS and forwards plain TCP to `host:port` |
| `rem_port:^` | Built-in HTTPS test responder |

In Docker, always use the three-part forms with an explicit destination host —
a compose service name, or `host.docker.internal` for a service on the Docker
host (add `--add-host=host.docker.internal:host-gateway` on Linux). The
two-part forms documented in `snif.conf` (e.g. `8080:^80`) resolve the
machine's own hostname, which inside a container is the container itself.

`rem_port` must be one of the ports served by the relay; the public VESvault
relay serves `443 465 993 1080 1443 7357 8080 8443 60001..60008`.


## Compose: TLS terminated by the connector

The simplest setup — the app speaks plain HTTP, the connector terminates TLS,
and the plaintext never leaves the compose-internal network
([compose.yaml](compose.yaml)):

```yaml
services:
  snif:
    image: ghcr.io/vesvault/snif
    volumes:
      - snif-etc:/etc/snif
    environment:
      SNIF_CONN_PORTS: "443:web:^80"
    restart: unless-stopped

  web:
    image: nginx:alpine
    restart: unless-stopped

volumes:
  snif-etc:
```

Once authorized, `https://{snif_hostname}/` serves the nginx page from
anywhere on the Internet.


## Compose: end-to-end TLS in the app

For TLS terminated by the app itself, share the volume read-only and point the
app at the SNIF certificate and key:

```yaml
services:
  snif:
    image: ghcr.io/vesvault/snif
    volumes:
      - snif-etc:/etc/snif
    environment:
      SNIF_CONN_PORTS: "443:web:443"
    restart: unless-stopped

  web:
    image: nginx:alpine
    volumes:
      - snif-etc:/etc/snif:ro
      - ./nginx-tls.conf:/etc/nginx/conf.d/default.conf:ro
    restart: unless-stopped

volumes:
  snif-etc:
```

with `nginx-tls.conf`:

```
server {
    listen 443 ssl;
    ssl_certificate     /etc/snif/snif.crt;
    ssl_certificate_key /etc/snif/snif.key;
}
```

`snif.key` is owned by uid 909 with mode 0640; a process that reads it must
run as root (like the official nginx image), as uid 909, or with a
supplemental gid 909. The certificate renews on the volume automatically; have
the app reload it periodically (e.g. `docker compose exec web nginx -s reload`
in a cron job), or terminate TLS in the connector instead.

For an app running on the Docker host rather than in a container, bind-mount a
host directory (`-v /etc/snif:/etc/snif`) instead of a named volume and point
the app at the files there.


## Self-hosted relay

Set `SNIF_CONN_INITURL` (and `SNIF_CONN_APIURL` if your relay requires it) to
your own relay — see [`ca-proxy/README`](../ca-proxy/README) for running one.
Everything else works the same.


## Build the image locally

```sh
git clone https://github.com/vesvault/snif.git
cd snif
docker build -t snif .
```

The multi-stage build compiles `snifd` on Alpine; the runtime image is a few
megabytes of OpenSSL, libcurl, and the connector binary, running as the
unprivileged user `snif` (uid 909).


## Security

- The private key is generated inside the container on first run and is
  never transmitted anywhere; the relay sees only an opaque, SNI-routed TLS
  stream.
- Certificate issuance and any relay misbehavior are publicly auditable
  through the CA Certificate Transparency logs.
- See [security-model.md](../security-model.md) for the trust model and
  [SECURITY.md](../SECURITY.md) to report vulnerabilities.
