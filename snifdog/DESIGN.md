# snifdog — the SNIF CA Transparency watchdog

## Why it exists

SNIF's trust model makes one load-bearing promise (`security-model.md`
guarantee #3):

> The relay cannot **silently** impersonate the device. It cannot produce a
> certificate matching the device's private key. Any certificate mis-issued for
> the device's hostname appears in public **Certificate Transparency** logs,
> making relay or CA misbehavior **publicly detectable**.

…backed by a trust assumption: *"the CA behind the CA proxy issues certificates
correctly, and CT logs are monitored. SNIF's detectability guarantee rests on
CT, not on trusting the relay."*

That assumption currently has no owner. Nothing actually monitors CT. **snifdog
is that monitor** — the component that turns "publicly detectable" into a
running detector that barks. Without it, guarantee #3 is a claim; with it, it is
an operating control.

## What it detects

A publicly-trusted certificate issued for a SNIF hostname or wildcard whose
private key the legitimate device does **not** hold. Concretely, the adversaries
this catches:

- a rogue or coerced public CA mis-issuing for a `*.snif.xyz` name;
- a compromised relay standing up its own ACME flow to impersonate a device;
- any mis-issuance, whether malicious or accidental, in the SNIF namespace.

It does **not** try to detect device/key compromise, relay availability abuse,
or application-layer attacks — those are out of scope per `security-model.md`.

## Design keystone: pin the SPKI, not the fingerprint

SNIF **binds one key to one name for life** — a device never re-keys; a new key
gets a new `snif-xxxx` name. The certificate issuance path reuses the device's
stored CSR on every renewal (`ca-proxy/bin/snif-certd` loads `csr/<domain>.csr`;
`ca-proxy/bin/snif-arc` retires certs older than 75 days so `snif-certd`
reissues). Consequence:

> A name's **SubjectPublicKeyInfo (SPKI) is immutable.** Across the ~75-day
> renewal cycle only the serial and validity window change, and there is no
> legitimate re-key that could ever change it. So **any** conflicting SPKI for a
> name is, unambiguously, a mis-issuance — the watcher has no rotation
> false-positive class to reason around.

Therefore snifdog pins the **SHA-256 of the DER SPKI**, not the whole-cert
fingerprint:

- a legitimate renewal (same key, new serial) → **silent**, no false alarm;
- a key-substitution impersonation (a cert for the same name whose key the
  attacker holds) → **fires immediately**.

This is a precise, low-noise match to the guarantee's own words — *"cannot
produce a certificate matching the device's private key."* SPKI mismatch **is**
the impersonation signal. (SPKI hashing follows the RFC 7469 pin construction:
`openssl x509 -pubkey | openssl pkey -pubin -outform der | sha256`.)

## Run modes (independent first, one tool)

snifdog leads with the trust-minimizing mode and adds the operator mode as
enrichment. Selected by config `mode = watch | reconcile | both`.

### 1. `watch` — independent watcher (default, no ledger)

Watches CT for a name/wildcard and alerts on any observed SPKI outside the pin
set. Requires **no** access to the CA-proxy ledger, so it can be run by a device
owner or an unrelated third party. It trusts **neither the relay nor the CA-proxy
operator** — which is the only configuration that actually *delivers* guarantee
#3, and the strongest engagement story ("don't take our word that it's
detectable — run the detector yourself against `*.snif.xyz`").

Anchoring the pin set:

- **First-seen anchor (default).** snifdog scans the *entire* CT history for each
  watched name and pins its SPKI as the trust anchor. Since SNIF never re-keys a
  name, legitimate history holds exactly one SPKI per name, so the anchor is
  unambiguous and every later cert must match it — a different SPKI (on the name
  *or an overlapping up-level wildcard*) is a **collision** → alert. Because SNIF
  hostnames are pseudo-random allocations valid only *after* the CA proxy
  allocates them, an attacker cannot pre-seed a rogue anchor for a name that does
  not yet exist.
- **Explicit pin (override, strongest).** The device already holds its cert and
  key at `/etc/snif/snif.crt`. `snifdog pin <name> --from /etc/snif/snif.crt`
  records the SPKI directly, overriding whatever history shows. The device
  *knows* its own key — no relay, ledger, or CA trust needed. Recommended for a
  device owner watching their own name.
- **Issuer allowlist (secondary).** Optionally pin the expected issuer (Let's
  Encrypt) as an extra signal. Not primary — a rogue cert with a different key
  fires on SPKI regardless of issuer.

### 2. `reconcile` — operator enrichment (co-located with the CA proxy)

When run on the relay host, snifdog cross-checks every CT observation against the
**CA-proxy CSR set** under `SNIF_CA_PROXY` (`csr/`). csr/ is the authoritative
key set: the proxy issues every cert from its `csr/<name>.csr` (`snif-certd`
`load_csr`) and a device never re-keys, so csr/ already holds every key the proxy
ever legitimately requested, and it is permanent (`snif-arc` rotates `crt/`→`arc/`
but never touches `csr/`). The delivered `crt/`/`arc/` certs therefore add no key
csr/ lacks — and indexing them would be *worse*, laundering a compromised-proxy
cert into "known-good" — so they are not consulted. This:

- **auto-classifies** observed certs (key ∈ the CSR set → known-good; absent →
  suspicious), eliminating false positives from the operator's own reissues that
  a pin set had not yet learned;
- **validates the key against ground truth, name-bound.** The CSR-set check above
  is SPKI-set membership (is this key *anywhere* in our issuance history). The
  stronger check is per-name: the CA proxy keys exactly one CSR per issued name at
  `csr/<apex>.csr`, and since SNIF never re-keys a name, that CSR's SPKI is the
  *only* key the name may ever present. So for every **local relay domain** — a
  subdomain of a base listed in the CA proxy's `etc/<init-domain>.domains` — the
  first cert observed has its SPKI checked directly against `csr/<apex>.csr`. A
  match anchors as `csr-verified` (proven-legit, stronger than trust-on-first-use,
  so it also closes the first-in-history poisoning window for these names); a
  **mismatch alerts immediately** as a provable mis-issuance, and the foreign key
  is never anchored. **A device zone the proxy holds _no_ CSR for is likewise a
  provable mis-issuance** — issuance always loads `csr/<zone>.csr` first, so a cert
  for an unprovisioned zone in our namespace was never requested through us — and
  alerts too. (Infra names in `SNIFDOG_NAME_ALLOW` — the init domain, pool host,
  base apex — are not device zones; snifdog ignores them entirely, so they never
  reach this check.) Enabled automatically whenever `${SNIF_CA_PROXY}/csr` exists.
- catches **external-CA compromise** the operator did not initiate;
- produces a proof-grade **evidence bundle** (below).

Weaker trust posture — a *malicious* operator can silence their own snifdog — so
this mode complements, never replaces, independent watchers. It is operational
hygiene and accountability, not the root of the guarantee.

## Historical backfill, anchoring & cursor

The watcher's trust anchors are derived from the **full CT history** of the
namespace, not from the moment snifdog starts:

1. **Backfill from the beginning.** On first run, enumerate every cert ever
   logged for the watched namespace, ordered by CT timestamp. Exact tie ordering
   is unimportant — legitimate history is single-SPKI per name, so the anchor is
   the same either way; ordering only labels which SPKI is "provisional-trusted"
   when a conflict *already* exists, and a conflict alerts regardless.
   **The first run must use crt.sh, not the steady-state certspotter source.**
   certspotter's free plan returns only *currently-valid* certs — expired
   issuances are silently omitted, and `expired=true` is rejected
   (`not_allowed_by_plan`). On `snif.xyz` that is the difference between ~20
   still-valid device zones and the ~58 zones / full history crt.sh returns
   (it serves expired certs, no plan gate). So until it has seeded once, snifdog
   triggers a one-shot crt.sh full-history sweep (`SNIFDOG_BACKFILL=1`, default)
   to seed the pin DB, then hands off to certspotter for cheap incremental
   polling. The seed is gated on a dedicated `var/backfill.done` marker, **not**
   the certspotter cursor: crt.sh 5xx's often, and if the seed were gated on the
   cursor a crt.sh outage on first run would be masked by the certspotter pass
   saving its cursor and would *permanently* skip the backfill. With the marker
   (written only on a successful sweep) the certspotter pass still covers live
   certs while the seed simply retries next pass until it completes. This is
   coverage-only: a live impersonation cert is valid *now*, so certspotter sees
   it regardless — the backfill exists so the pin DB reflects every name the
   relay has ever served, not just today's.
2. **Anchor = the name's SPKI.** For each distinct name (wildcard parent), pin its
   SPKI — legitimately there is exactly one.
3. **Report pre-existing collisions.** If history already holds two distinct
   SPKIs for one name, surface it on the first run — since SNIF never re-keys,
   that is a past mis-issuance, exactly what an operator wants to see on day one.
4. **Steady state (coverage-aware).** Each newly observed cert is checked against
   the anchor of every pinned name its SANs cover — the exact name, and **any
   up-level wildcard that overlaps it** (e.g. a `*.snif.xyz` or `*.snif-pool…`
   cert valid for a pinned host). A differing SPKI on any overlap is a collision →
   alert. A precertificate is not a special case: same name + same SPKI passes the
   equality check for free; only a *differing* SPKI conflicts.

**Key invariant — the pin DB is a pure function of CT history.** Given the same
logs, a full re-scan always reconstructs the same anchors and the same
collisions. This makes the watcher stateless-safe: state is an optimization, not
a source of truth.

**Cursor = optimization, re-scan = fallback.** To avoid re-reading all of history
every pass, snifdog persists the source's forward cursor (`var/<source>.cursor`)
and resumes from it. The cursor is trusted only while it works: if the source
rejects or has pruned it (stale / out of range), snifdog **restarts from the
beginning** and reconverges — correctness is never at stake, only the work of one
rescan. certspotter's `after=<id>` issuance id is a persistent, monotonic cursor
and the primary path; crt.sh has no server cursor, so there the "cursor" is just
the max-seen crt.sh `id` high-water mark and a periodic full re-fetch is the norm.

**Edge cases and the one residual caveat:**

- **No legitimate re-key to explain a conflict.** SNIF never re-keys a name (a new
  key gets a new name), so a name's SPKI is fixed for life and any conflicting
  SPKI is an unambiguous alert — there is no rotation false-positive class to
  suppress.
- **Precertificates are not a special case.** A precert and its final cert carry
  the same name and same SPKI, so the equality check passes them for free; only a
  *differing* SPKI conflicts.
- **First-in-history poisoning** is the one residual risk (an attacker who logs a
  rogue cert for a name *before* the legitimate device ever does). The random,
  operator-allocated `snif-xxxx` namespace makes pre-seeding a not-yet-allocated
  name impractical; explicit pinning removes it entirely for a device owner who
  anchors from their own key.

## Wildcard-privacy interplay (no regression)

The CA proxy issues **wildcard** certs (`snif-certd` loads the CSR as
`*.<domain>` in DNS mode), so CT exposes only `*.snif-xxxx.snif.xyz`, never the
per-device host label (`security-model.md` "Hostname privacy"). snifdog keys on
the **registered wildcard parent**: a device pins its wildcard's SPKI, and an
impersonation is a *second* cert for that same wildcard with a different key →
detected. Watching does not weaken hostname privacy.

## CT data source (pluggable)

The source is an adapter; the durable core is SPKI reconciliation + alerting.

- **M1 default — certspotter API.** `GET
  https://api.certspotter.com/v1/issuances?domain=snif.xyz&include_subdomains=true&expand=dns_names&expand=cert_der`
  returns the cert DER inline and pages via a persistent, monotonic `after=<id>`
  issuance cursor. Backfill starts at `after=0` and streams the full history in
  order; steady state resumes from the saved cursor. Ideal for a watcher (DER in
  one call, no second fetch, resumable). **Caveat — live coverage only:** the
  free plan returns only unexpired certs (`expired=true` is `not_allowed_by_plan`),
  so `after=0` does *not* actually reach historical/expired issuances. This is
  fine for steady-state detection (an active rogue cert is unexpired) but means
  the initial anchor set is seeded from crt.sh instead — see "Historical
  backfill" above.
- **M1 fallback — crt.sh.** `GET https://crt.sh/?q=%25.snif.xyz&output=json`
  returns the full history in one (large, paginated) query; the PEM for each needs
  a second `GET https://crt.sh/?d=<id>`. No server cursor — order by
  `entry_timestamp`, keep a max-seen `id` high-water mark, re-fetch + diff.
- **M2 — direct CT polling.** Poll `get-sth` / `get-entries` across the Google
  log list, verify the STH signature and Merkle **consistency** proofs, filter
  for the SNIF namespace. Removes the third-party-aggregator trust and matches
  SNIF's ethos. Heavier (STH/ECDSA verification, tree math); deferred to M2.

M1 accepting a third-party aggregator is acceptable because a *lying* aggregator
can only hide a rogue cert, not forge a false alarm; M2 closes even that gap.

## On detection

For each new CT cert whose SAN set intersects a watched namespace, snifdog
extracts SANs, SPKI hash, serial, issuer, validity, and the carrying log/SCT,
then:

0. (co-located, local relay domain) SPKI ≠ the name's `csr/<apex>.csr` key, **or**
   the proxy holds no CSR for a device zone it is authoritative for →
   **ALERT** at once (provable mis-issuance; foreign key not anchored). SPKI = the
   CSR key → **OK**, anchor `csr-verified`. This name-bound check runs first
   because it is ground truth, not inference.
1. SPKI ∈ pin set for a matching name → **OK** (known-good renewal), record and
   move on.
2. else, in `reconcile` mode, look up the SPKI in the CSR set (`csr/`) → if
   present it is a legit issuance the pin set had not learned: **auto-learn** the
   pin and emit a low-severity notice.
3. else → **ALERT**: a cert for a SNIF name with an unrecognized key.

An alert produces:

- a structured line to **syslog** (`Sys::Syslog`) and non-zero **exit** (so a
  cron wrapper surfaces it);
- optional **webhook** POST and **email**;
- an **evidence bundle**: the offending cert DER, its SCTs, which log carried it,
  and (operator mode) the "no matching CSR" attestation. Because
  CT is non-repudiable, this bundle is proof-grade evidence of CA or relay
  misbehavior.
- optional, opt-in: signal the local connector to **stop presenting its
  identity** (strong action, off by default).

## Component shape (standalone, Perl)

Ships as a first-class component in the snif repo, parallel to `snifd/` and
`ca-proxy/`, reusing the ca-proxy toolchain (LWP, Crypt::OpenSSL::X509, the
cron/FIFO idioms of `snif-certd`/`snif-arc`).

```
snifdog/
  README
  DESIGN.md              # this design note
  bin/snifdog            # watcher: `pin`, `poll` (cron), `watch` (daemon)
  etc/snifdog.conf       # namespaces, CT source, pins dir, alert sinks, mode
  lib/Snif/CT/*.pm       # source adapters: CertSpotter.pm, CrtSh.pm, (M2) Log.pm
  pins/                  # one SPKI pin record per watched name/wildcard
  var/                   # per-source cursor + seen-id cache (idempotent, cron-safe)
```

Perl dependencies:

- HTTP — `LWP::UserAgent` + `LWP::Protocol::https` (JSON APIs; M2 CT endpoints).
- JSON — `JSON::PP` (core).
- X.509 — `Crypt::OpenSSL::X509` for SANs/serial/issuer/validity; SPKI SHA-256
  via an `openssl` shell-out (matches the RFC 7469 operator mental model).
- Alerts — `Sys::Syslog` (core), LWP POST for webhooks, `sendmail`/SMTP for email.
- M2 only — `Digest::SHA` (core) for Merkle/STH; ECDSA STH-sig verification.

CLI sketch:

```sh
snifdog pin mydevice.snif-1a2b.snif.xyz --from /etc/snif/snif.crt
snifdog poll         # one incremental pass; cron */15
snifdog watch        # long-running loop
```

Install/run mirrors ca-proxy: a minimal `Makefile.am` for install + an
`etc/systemd` unit and a cron example; no autotools logic needed beyond install
paths (pure Perl).

## Phasing

- **M1** — `watch` mode: SPKI-pin watcher over certspotter (crt.sh fallback) for
  `*.snif.xyz`, explicit-pin + TOFO, syslog/webhook/email alerts, evidence
  bundle. `reconcile` mode against the ca-proxy CSR set when co-located. Deploy on
  the live relay → guarantee #3 becomes an operating control.
- **M2** — direct CT log polling with STH signature + Merkle consistency
  verification; drops the aggregator trust.
- **M3** — connector integration: the connector records its issued cert's SPKI +
  SCTs and exports a pin file (or an embedded self-watch in libsnif), so a device
  self-monitors with zero configuration.

## Docs / engagement wiring

- This design note (`snifdog/DESIGN.md`), then the `snifdog/README`.
- A paragraph in `security-model.md` wiring snifdog into guarantee #3 and the
  "CT logs are monitored" assumption — naming the tool that discharges it.
- A README / Show HN bullet: SNIF not only claims misbehavior is CT-detectable,
  it ships the watchdog and anyone can run it against the public namespace.
- Consider a public snifdog feed for `*.snif.xyz` operated by VESvault as a
  reference deployment (dogfooding the guarantee).

## Open questions for the build

- **certspotter vs. crt.sh as the M1 default** — *resolved:* certspotter's
  persistent cursor + inline DER is the steady-state source, but its free plan
  cannot serve expired certs (`expired=true` → `not_allowed_by_plan`), so it can
  never do the *full-history* backfill. Split the roles: first run seeds from
  crt.sh (full history incl. expired), then certspotter drives cheap incremental
  polling. Keyed off the presence of the stored certspotter cursor.
- **Up-level wildcard scope** — beyond the per-device `*.snif-xxxx.snif.xyz`,
  which broader names must be watched as overlap threats (`*.snif.xyz`, `snif.xyz`,
  `*.snif-pool.snif.xyz`)? Enumerate the covering set once from the namespace
  layout.
- **Evidence-bundle sink** — local dir vs. also POST to a collection endpoint;
  where the operator reference feed publishes.
- **Connector self-watch (M3)** — external `snifdog` process reading the pin file
  vs. embedded in libsnif; embedding is heavier but zero-config for devices.
