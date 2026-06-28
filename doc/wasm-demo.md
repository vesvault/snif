# SNIF in-browser live demo (wasm connector)

A live, clickable demo that beats a recorded GIF: a visitor's **browser tab
becomes a real SNIF connector** — it gets a real, browser-trusted certificate
for a real `*.snif.xyz` hostname and (M2) serves live HTTPS that the relay
cannot read. No account, no install.

This is the engagement artifact tracked in the relicense/launch plan; it
supersedes the `doc/demo.tape` VHS GIF as the headline (the GIF can stay as an
inline preview, ideally recorded against this demo).

## Why a recorded GIF is the wrong headline

The whole pitch — *a device behind NAT gets a real CA cert on a real public
hostname through a relay that can't read it* — is most convincing when it is
**real and clickable**, not a canned terminal capture. A browser tab is itself
"a device behind NAT," so the demo is literally the product working.

## Hard constraint that shapes everything

Browser wasm has **no raw TCP** and no listening sockets (sandbox boundary, not
a wasm gap; Emscripten's POSIX sockets just tunnel over WebSocket anyway; the
Direct Sockets `TCPSocket` API is Isolated-Web-App-only and unusable for a
public page). So *something* must translate browser transport ↔ the relay's raw
TCP. Decision: **a websockify-style WS↔TCP bridge in front of the relay**
(ports `snif`/7123 and the service pool/7120). **`snifd` is not modified** — the
bridge is pure demo infrastructure on snif.host. (Native WebSocket inside
`snifd` is a possible later productionization; not needed for the demo.)

## The key architectural fact (from the relay code)

The control connection (`snifd/ctl.c`) has the **relay as the TLS *client*** and
the **connector as the TLS *server***: the connector proves it holds the
`*.snif.xyz` private key by completing the handshake, and the relay matches
`SNIF LISTEN <host>` against the cert CN. Each forward connection
(`snifd/fwd.c`, `SNIF_WF_TERMTLS`) likewise has the connector `SSL_accept`-ing
the **visitor's** TLS and serving the built-in `snif_fwd_test` page.

Therefore the browser must run a **TLS *server* in wasm**, over memory buffers
fed by the WebSocket, for both connections. The relay sees only opaque bytes —
the trust model is preserved (the outer `wss://` is just transport framing,
terminated at the relay edge; the inner end-to-end TLS keys live only in the
tab).

## Crypto: wolfSSL, and keep wasm to the TLS engine only

OpenSSL-in-wasm is heavy and painful; the build host already has a **1.2 MB
`libwolfssl.a` built for wasm** (`/tmp/wolfssl`) and an established wiring
pattern (`/usr/src/wasm-ec`: thin C shim + `*init.js`, `emmake make`, link
wolfSSL). The minimal-bloat split:

| Piece | Where | wasm cost |
|---|---|---|
| Protocol framing (`lib/conn.c`, OpenSSL-free text lines) | JS, or compile conn.c | ~0 |
| Key generation + CSR | wolfCrypt-wasm shim (EC P-256) | small |
| Cert issuance HTTP flow | `fetch` | 0 |
| `snif_fwd_test` response | JS string | 0 |
| WebSocket transport | JS `WebSocket` (no emscripten sockets) | 0 |
| **TLS server over memory buffers** | **wolfSSL-wasm shim (mirror wasm-ec)** | the 1.2 MB already built |

Only the visitor-TLS termination genuinely needs a TLS library; everything else
stays out of wasm.

## Cert issuance flow (CA proxy — pure HTTP, ideal for fetch)

1. `GET` init URL (`https://snif.snif.xyz:4443/`) → relay allocates
   `*.snif-xxxx-yyyy.<domain>`, returns it in `X-SNIF-CN` (`snif-auth.php`).
2. `PUT /snif-cert/<host>.csr` with the CSR → `201` (`snif-cert.php`).
3. **Authorization gate** — today `snif_auth_ves()` checks an
   `X-VES-Authorization` vaultItem token and enforces a per-email quota
   (`inc/snif-auth-ves.php`). **The captcha replaces exactly this gate.**
4. `GET /snif-cert/<host>.crt` polls until ACME issues the real cert.

## Milestones

### M1 — "your browser just earned a real CA cert, no account, no install"
Browser allocates a real `*.snif.xyz` hostname and obtains a real browser-trusted
cert, captcha-gated. **No relay changes, no WebSocket, no wasm TLS.**
- [x] Server: captcha authorization path on the CA proxy
  (`inc/snif-auth-captcha.php`), wired into `snif-auth.php` (VES path untouched).
  Quota protection moves from per-email (VES) to per-IP + global/day.
- [x] Server: serve the **cert API over HTTPS on the init origin** to kill the
  mixed-content block. The per-host catch-all endpoint is `http://` *and* has no
  cert until issuance, so it's unreachable from an HTTPS page — a hard block, not
  a warning. Resolution uses the existing `apiurl` override (`cert->apiurl`,
  `lib/cert.c` — a full base-URL prefix, `<apiurl><cn><suffix>`): browser sets
  `apiurl = https://snif.snif.xyz:4443/snif-cert/`. Server changes:
  `snif-cert.php` now derives the CN from the request **path** (was `HTTP_HOST`,
  which only matches the catch-all); `secure_html/snif-cert.php` wrapper + a
  `secure_html/.htaccess` route expose it on `:4443`; CORS gains PUT/OPTIONS,
  `X-SNIF-Captcha`, and `always`-set + `Expose-Headers` (X-SNIF-CN/AuthUrl) so
  the browser can read the 401 cert-poll headers cross-origin.
- [x] Keygen + CSR via a **wolfCrypt-wasm shim** (EC P-256), `wasm/SnifCert.c`,
  mirroring `wasm-ec/WasmECDH.c`. Chosen over WebCrypto+libVES.Util ASN.1 to keep
  one crypto stack/key lifecycle through M2. **BUILT + VERIFIED**: 155K wasm
  against an isolated wolfSSL built `--enable-cryptonly --disable-asm --enable-ecc
  --enable-keygen --enable-certgen --enable-certreq`; produces a CSR that passes
  `openssl req -verify`. Gotcha fixed: `wc_InitCert` defaults version to X.509 v3
  (2) but a PKCS#10 CSR's version MUST be 0 — set `req.version = 0` or OpenSSL/LE
  reject the signature. (`--disable-asm` is required: wolfcrypt `cpuid.c` has x86
  inline asm that won't compile to wasm.)
- [x] Demo page (implemented in the **snif.host** repo, `public_html/demo/`,
  served at `https://snif.host/demo/`): `snif-conn.js` (the in-browser connector
  flow) + `index.html` (UI + Turnstile widget). `SnifConn.issue()` runs the exact
  `lib/cert.c` contract — allocate CN (`GET <apiBase>`, read `X-SNIF-CN`), generate
  the key + CSR in wasm with the **full** (wildcard) CN as the subject, `PUT` the
  CSR to `<apiBase>snif-cert/<base>.csr` (the `*.` stripped for the path, per
  `snif_cert_basecn`), authorize by posting the Turnstile token in the
  `X-SNIF-Captcha` header, then poll `<base>.crt` through `503`/`401` until `200`.
  CORS-clean (the preflighted PUT/POST and the exposed `X-SNIF-CN`/`X-SNIF-AuthUrl`
  headers are all covered by the `secure_html/.htaccess` rules). The wasm crypto
  path is verified through the JS wrapper offline: `test-node.js` →
  `SnifConn.makeCSR()` → `openssl req -verify` OK, subject CN keeps the wildcard.
  (Build needs `HEAPU8` in `EXPORTED_RUNTIME_METHODS` — the wrapper reads the key
  DER as raw bytes, which `UTF8ToString` can't do.)

### M2 — "open this URL on your phone"
Browser tab becomes a live HTTPS server. **All client + bridge code is built and
verified end-to-end** (loopback, mock relay, and the full WS-bridge path); the
only thing left is exercising it against the *production* relay + a real LE cert,
which is gated on the M1 deployment (same blocker).

- [x] **wolfSSL-wasm TLS *server* shim over memory buffers** —
  `public_html/demo/SnifTls.c` (+ `Makefile.tls`, built `SnifTls.js`/`.wasm`).
  A wolfSSL server driven with zero sockets: two in-memory byte queues + custom
  `wolfSSL_CTX_SetIORecv/SetIOSend` callbacks, exposed to JS as
  `new/setcert/setkey/start/feed/accept/drain/read/write/shutdown/free`. Loads
  the leaf+chain PEM and the **same ECPrivateKey DER `SnifCert_keyder` already
  exports** (no separate key import needed — M1 and M2 share one key/stack).
  Needs a TLS-enabled wolfSSL-wasm (server + ECC + supported-curves + aesgcm +
  sha384 + opensslextra + sni; **NOT `--disable-filesystem`** — wolfCrypt seeds
  its RNG from `/dev/urandom`, which emscripten emulates via
  `crypto.getRandomValues`; disabling it ⇒ `wc_InitRng -199` / `wolfSSL_Init
  -228`). **Verified**: a real node `tls` client completes a **TLS 1.3**
  handshake against the wasm server over the memory buffers, gets the presented
  EC cert, and reads back app data (`test-tls-node.js`).
- [x] **JS connector** `public_html/demo/snif-srv.js` (`SnifSrv.serve`) —
  transport-neutral, drives `SnifTls` for both connections, exactly per the relay
  source: **control** = pure TLS from byte 0 (relay is the TLS *client*,
  `snifd/ctl.c`), then `SNIF LISTEN <host>` + parse `SNIF CONNECT <connid> <srv>
  <fwd> <cln>` as TLS app-data; **forward** = a *plaintext* `SNIF ACCEPT
  <connid>` preamble (`snifd/srv.c` reads it with no TLS), then the relay
  blind-pipes the visitor's raw TLS, which the connector `SSL_accept`s and
  answers with the M2 analogue of `snif_fwd_test` (a small live HTML page).
  **Verified** end-to-end against a mock relay (`test-srv-node.js`).
- [x] **WS↔TCP bridge in plain PHP** `bridge/snif-bridge.php` — dependency-free
  (core `stream_*` + `sha1`, no Node/npm; fits the existing snif.host PHP stack).
  Single-process non-blocking `stream_select` loop, own RFC-6455 handshake +
  frame de-framing. Two fixed endpoints `/snif/ctl`→`relay:7123`,
  `/snif/srv`→`relay:7120` (fixed targets ⇒ no SSRF; the relay-supplied fwd
  host:port is ignored). Plain `ws://` on localhost, fronted by nginx for `wss://`.
  Browser transport `public_html/demo/snif-wsbridge.js`
  (`SnifWsBridge.makeTransport`). **Verified**: the whole browser path —
  `SnifSrv` → WebSocket → the real PHP bridge → mock relay, TLS 1.3 terminated in
  the connector (`test-bridge-php.js`).
- [x] Demo page: `index.html` gained a **"Make it live"** control (gated behind
  `?live=1`/`?bridge=` until the bridge is deployed) that lazy-loads `SnifTls.js`,
  builds the WS transport, and runs `SnifSrv.serve` with the issued cert + key,
  showing the live `https://<snifHost>/` and a served-request counter.
- [ ] **Live bring-up against the production relay** (needs M1 deployed + a real
  cert + the bridge running): point a phone at `https://<snifHost>/`.

## Operator setup notes (M1)

- Drop the Cloudflare Turnstile **secret** into `ca-proxy/etc/turnstile.secret`
  (presence enables the captcha path; absence → `501`). The public **site key**
  goes in the demo page — edit `SITEKEY` in the snif.host repo's
  `public_html/demo/index.html`, or pass `?sitekey=...` for testing. (For local
  dev use Cloudflare's test pair: site key `1x00000000000000000000AA` "always
  passes" + secret `1x0000000000000000000000000000000AA`.)
- Per-IP / per-day caps live in `inc/snif-auth-captcha.php`
  (`SNIF_CAPTCHA_IP_MAX`, `SNIF_CAPTCHA_DAY_MAX`); counters under `auth/captcha/`.
- **Build the wasm**: in the snif.host repo's `public_html/demo/`, source emsdk
  and `emmake make` against an isolated `--enable-cryptonly` wolfSSL (point `WOLF`
  at it). Produces `SnifCert.js` + `SnifCert.wasm`, committed there as web assets.
- **Deploy the page**: it ships with the snif.host site at `https://snif.host/demo/`
  (`public_html/demo/` — `index.html`, `snif-conn.js`, `SnifCert.js`,
  `SnifCert.wasm`, plus a `.htaccess` for the directory index + wasm MIME type).
  The page targets the absolute `apiBase` (default `https://snif.snif.xyz:4443/`)
  cross-origin; the CA proxy's CORS rules cover it.

## Operator setup notes (M2)

- **Build the TLS wasm**: in `public_html/demo/`, source emsdk and
  `make -f Makefile.tls` against an isolated TLS-enabled wolfSSL-wasm (see the
  Makefile header for the exact `./configure` — keep the filesystem on for the
  RNG seed). Produces `SnifTls.js` + `SnifTls.wasm` (~540K), committed there and
  **lazy-loaded only on "Make it live"** so M1 page-load stays light.
- **Run the bridge**: `php bridge/snif-bridge.php` (pure PHP, no npm; keep it up
  with systemd/supervisor — see `bridge/README.md`). Env: `RELAY_HOST` default
  `snif.snif.xyz`, `CTL_PORT` 7123, `SRV_PORT` 7120, `BRIDGE_PORT` 8765 on
  `127.0.0.1`. Front it with nginx for `wss://` — the page is `https://`, so it
  needs secure WS:
  ```nginx
  location /snif/ {
      proxy_pass http://127.0.0.1:8765;
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_read_timeout 300s;
  }
  ```
  The page defaults its bridge to the page origin `wss://<page-host>`
  (SnifWsBridge adds the fixed `/snif/ctl` & `/snif/srv` paths). Override with
  `?bridge=wss://host`. Enable the control with `?live=1` (auto-on when
  `?bridge=` is given).
- **Verify offline** (no relay/cert needed), from `public_html/demo/`:
  `node test-tls-node.js` (wasm TLS server loopback), `node test-srv-node.js`
  (connector vs mock relay), `node test-bridge-php.js` (full path through the PHP
  bridge — spawns `php`; the test's client side uses node `ws` to stand in for
  the browser WebSocket, the deployed server stays pure PHP).

## Follow-ups (separate discussions)

- **Switch the SNIF default key algo from RSA-4096 to EC across the whole
  codebase** (not just the wasm demo) — `lib/cert.c` `snif_cert_ctx` keygen,
  `SNIF_CERT_RSA_BITS`. RSA-4096 keygen is slow (badly so in wasm); EC has
  identical relay trust (the relay is key-type-agnostic). jz, 2026-06-24.
- Refactor `cert.c` to inject the HTTP transport via callback (decouple from
  curl) so device + browser could eventually share one source of truth.
