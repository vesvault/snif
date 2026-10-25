# SNIF relay cluster

**Status:** design, not implemented (2026-10-14, revised after the third
review). Items marked **open** are not settled. **Default** marks a value
chosen so the work can start; it can still change.

## 1. Scope

Two or more relays serving the same SNIF base domains, all active, normally
in different regions. A client that reaches any node gets through to a device
connected to any node. Losing a node drops only the connections on it, and
its devices reconnect to another one.

Every node links to every other node, so the peer links form a complete
graph (section 3). The rules below hold for any number of nodes, and two is
the smallest cluster. With no peers configured, every component behaves
exactly as it does today: a single relay needs nothing from this document.

Out of scope: how the nodes are provisioned, networked and monitored, which is
the operator's.

Terms used below:

- **node name**: a short identifier such as `nyc1`, used in file paths and
  settings. It is not a DNS name.
- **service address**: the host and port a node gives devices for service
  connections, `snifd -s`, set by `SNIF_RELAY_SRV`.
- **peer**: any other node of the cluster.
- **listed peers**: the nodes a node names in `SNIF_CLUSTER_PEERS`. Normally
  every node lists every other one (section 3.2).
- **pool name**: one name, such as `snif-pool.snif.xyz`, that every device
  hostname is an alias for (`*.<base>` CNAME the pool name), under every base
  domain the cluster serves.

## 2. Forwarding across nodes

The basic path already works with no change to snifd:

1. A client reaches node B with the SNI of host H. B holds no control
   connection for H, so it pushes `SNIF CONNECT <connid> <H>:<port>
   <srvhost>:<srvport> [<client-ip>]:<port>` to every output FIFO
   (`snif_cln_notify` and `snif_cln_pollfn`, `snifd/cln.c`).
   `<srvhost>:<srvport>` is B's own service address.
2. B has one output FIFO per peer, and a tunnel (section 3) carries each one
   into that peer's input FIFO. The node that holds H's control connection,
   say A, passes the line on unchanged (`snif_fifo_pollfn`, `snifd/fifo.c`).
   The others hold it (section 2.1).
3. H's connector opens its service connection to B's service address and
   sends `SNIF ACCEPT <connid>`. B joins it to the waiting client
   (`snif_srv_pollfn`, `snifd/srv.c`).
4. `CLOSE` and `ABUSE` from a connector about a connection that is not on its
   node are pushed as well (`snif_ctl_pollfn`, `snifd/ctl.c`). So abuse scores
   reach the node the client is on.

snifd acts on a line from an input FIFO locally and never writes it to
another FIFO (`snif_fifo_pollfn`). So a line crosses exactly one tunnel:
- **The links must form a complete graph.** A node's clients reach devices
  only on the nodes it has a tunnel to.
- **Lines cannot loop,** without any loop detection.
- **A peer's line never reaches this node's peripheral processes.**

One case does not work today: **a device that connects to another node after
the client arrived is never told about the client.** The client's `CONNECT`
is pushed once, when the client arrives, and every peer drops it, because
none of them holds a control connection for the host yet. When a control
connection opens, snifd sends it the `CONNECT` of each client waiting on
that node (`snif_ctl_sethost`), and none from peers. This is the usual case
for a device woken through `snif-apnsd`: the client waits on one node, and
the device, once awake, connects to whichever node its connector picks. With
two nodes, that is the other one about half the time. The client then waits
out its timeout, 60 s by default. Section 2.1 fixes it.

Requirements:

- **Each node advertises its own service address.** If every node names the
  pool name, a connector's DNS lookup picks a node at random, often not the
  one whose client is waiting. That node drops the unknown connection ID. The
  sample `SNIF_RELAY_SRV=snif-pool.snif.xyz:7120` in `etc/snif.conf` is
  therefore wrong for a cluster.
- **Node DNS names stay outside `snif-*.<base>`.** snifdog treats such names
  as device zones (`allocatable`, `snifdog/bin/snifdog`). It alerts on any
  certificate for one that has no CSR. Use names like `relay-nyc1.<base>`, and
  add them to `SNIFDOG_NAME_ALLOW` if they ever go into a certificate.
- **Tunnel FIFOs, one pair per peer:**
  - `var/snifd-out-peer-<peer>.ctl`: this node's pushes, read by the tunnel
    to that peer.
  - `var/snifd-in-peer-<peer>.ctl`: lines from that peer.

  `ca-proxy/bin/snif-relay` already hands every `var/snifd-out*.ctl` and
  `var/snifd-in*.ctl` to snifd. They sit beside the existing peripheral FIFOs
  such as `snifd-out-apnsd.ctl`, and snifd treats both kinds alike.
- **Every served name resolves through the pool name** (section 9): device
  hostnames, the init origin, and sites served through the static map (`-m`).

**When a tunnel is down,** its two nodes still serve their own devices and
use every other link. A client on one of them waits until the client timeout
for a device on the other. The output FIFO has no reader, so snifd's writes
fail and the lines are dropped (`snif_fifo_restart`); nothing queues. Neither
end notices, so each link needs its own health check (section 7.1).

**Default, optional:** a node drops a `CONNECT` read from an input FIFO whose
service address is not a listed peer's. Otherwise a line written into a
tunnel reaches the connector as it is, and the connector connects wherever the
line says (`snif_conn_receive_cb`, `lib/conn.c`; `snif_fwd`, `snifd/fwd.c`).

### 2.1 Held CONNECTs

A `CONNECT` read from an input FIFO, for a host with no control connection
on this node, is held instead of dropped. Every peer without the host holds
it. When a control connection for that host opens, `snif_ctl_sethost` sends
it the held lines after the `CONNECT`s of its own node's waiting clients.

The node the client reached already pushes the end of every such connection
to every output FIFO, so every node holding the line sees it. A held line
goes away on whichever comes first:

- `SNIF CLEAR <connid>`: a service connection accepted the client
  (`snif_srv_pollfn`, `snifd/srv.c`);
- `SNIF CLOSE <connid>`: the client went away before that
  (`snif_cln_free`, `snifd/cln.c`);
- the client timeout, counted from when the line arrived. This only covers
  a `CLEAR` or `CLOSE` lost in a tunnel restart.

Held lines are found by connection ID alone. The ID is unique across nodes:
it is a digest of the client's first bytes, which include the ClientHello's
32 random bytes (`snif_cln_pollfn`). Only a replayed ClientHello repeats an
ID, and that can cost at most the replayed connection.

A held line delivered late costs one service connection that the client's
node refuses, because the connection ID is no longer waiting.

The held lines have a cap per node (**default** 4096), and the oldest goes
first. Every client that reaches a node for a host that node does not hold
puts one on every peer, scanners included. So each node holds lines from
every peer, and its share grows with the number of nodes.

No line goes out twice, so peripheral processes see each connection once,
and `snif-apnsd` wakes a device only from the node the client reached.

### 2.2 Peripheral processes

Peripheral processes run on each node and see only that node:

- the pushes of its own clients and connectors, including a connector's
  `SNIF MSG`;
- a `SNIF MSG` written into its input FIFO, which reaches the device only
  when the device is connected to that node (`snif_fifo_pollfn`).

There is no forwarding of `MSG` between nodes. A peripheral process whose
state must hold on every node keeps it in CA proxy files that the sync
carries. `snif-apnsd` does this with its wake tokens in `apns/` (section 4).
A peripheral process that must reach a device wherever it is connected
writes to every node's input FIFO. None in this repository writes `MSG`
lines at all.

A connector's `MSG` also crosses every tunnel, because a tunnel is an output
FIFO like any other. Each peer hands it only to its own control connections
for that host, if any. The node it was sent to hands it to its other control
connections for that host, never back to the sender (`snif_ctl_pollfn`), so
devices that share a name hear each other wherever they are connected. The
relay does not refuse a second connection for a name, which can be the same
device back after a network problem; such devices learn of each other
through `MSG`. The protocol allows that: draft-05 §4.1 says a
`SNIF MSG` may reach a connector once per cluster node, and that connectors
must process it idempotently.

## 3. Peer link

Every pair of nodes is linked in both directions, on two channels, both over
ssh. With N nodes:

| | Per node | In the cluster |
|---|---|---|
| FIFO tunnels it starts | N-1 | N(N-1) |
| Sync sessions it starts | N-1 | N(N-1) |
| `authorized_keys` lines for `snif-peer` | 2(N-1) | 2N(N-1) |

Three nodes make 12 ssh connections in all, and five make 40.

- **FIFO tunnel:** each node runs one systemd unit per peer, an instance of
  `snif-tunnel@<peer>.service`, restarting always. It runs
  `ca-proxy/bin/snif-tunnel <peer>`, which takes the peer's address from
  `SNIF_CLUSTER_PEERS` and runs:

  ```
  ssh -o BatchMode=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
      snif-peer@<peer-address> < var/snifd-out-peer-<peer>.ctl
  ```

  On the peer, that key's `authorized_keys` line is
  `restrict,command="cat > <CA_PROXY>/var/snifd-in-peer-<node>.ctl"`. The key
  names the node, so no node can write into another node's input FIFO.
  - Opening the output FIFO for reading blocks until snifd opens it for
    writing.
  - When either snifd restarts, the pipe breaks, ssh exits, and the unit
    starts it again.
  - `ServerAliveInterval` matters. Without it, a connection dropped somewhere
    between the regions leaves ssh running while nothing flows.
- **Sync channel:** each node keeps one session open to each peer:
  `ssh snif-peer@<peer-address>`, with the forced command
  `snif-syncd --serve <node>`, the key again naming the node. It is a line
  protocol over stdin and stdout (section 7.3). A node sends its requests on
  its own outgoing sessions and answers each peer's on that peer's incoming
  one.
- **Account:** `snif-peer`, a member of the CA proxy's group, since the CA
  proxy directories are group-writable (`ca-proxy/mkdirs`).
  - Shell `/bin/sh`, because forced commands run through it. No password.
  - One key per peer per forced command.
  - The install makes only `snif`. The operator makes `snif-peer`, its
    keys and the sshd settings that confine it.
- **Network:** chosen by the operator. ssh authenticates and encrypts on any
  path. A private network between the nodes keeps port 22 off their public
  interfaces.
- **Why ssh rather than a link built into snifd:** snifd is the
  internet-facing process. A peer listener with its own authentication would
  make it bigger, while ssh's authentication is already reviewed and each key
  can be limited to one command. The FIFO line format is what crosses either
  way, so a native link can replace ssh later without changing anything else.

### 3.1 Detecting a dead peer

Every rule here is per peer. A node can reach some peers and not others.

- **Deadline:** every request a client waits on (`LEASE`, `CSR`, and the `GET`
  behind a `FETCH`) has a deadline, 3 s by **default**. A request that goes
  to every peer is sent to all of them at once, so it waits for the slowest
  answer, not for the sum.
- **Heartbeat:** each node sends `PING` on each sync session every 5 s
  (**default**). Three missed replies, or the ssh process exiting, mark that
  peer down.
  - While a peer is down, requests that need it are answered at once
    (`UNREACHABLE`, `ALONE`) instead of each waiting out its deadline.
  - The session reconnects with backoff.
- **A missed deadline closes that session,** which then reconnects. Whatever
  was in flight on it counts as unknown, and no reply can ever be matched to
  the wrong request.
- **Unknown never means yes.** A lease that was not confirmed is not held. A
  CSR that was not confirmed is not accepted.
- **Closing a session does not stop a request already sent.** Its bytes may
  have reached the peer and be acted on later. The lease rules in section 6
  make such a late request harmless.

### 3.2 Membership

- **Only listed peers can write.** A node answers `LEASE`, `CSR` and `PUT`
  only from nodes it lists, and answers any other node `REJECT member`. It
  answers `GET` and `LIST` for any node holding a peer key, so that a node
  can copy state before it joins.
- **A node accepts a CSR only with an answer from every listed peer**
  (sections 5 and 6). So a node that is down pauses new enrolments on every
  node that lists it, and a link that is down pauses them on its two ends.
  Renewals carry on.
- **Why CSRs cannot split:** two nodes can never hold the same CSR lease at
  once if they list each other, or if they list a common peer. In both cases
  one node's grant record decides between them (section 6). Removing only
  nodes that are down or stopped keeps every pair of remaining nodes listing
  each other.

**Evicting a node that stays down:**
1. Make sure it is down, or stop it, snifdog included. Otherwise its snifdog
   reports every name the others accept without it as never provisioned.
2. Remove it from `SNIF_CLUSTER_PEERS` on every other node, in any order. A
   node that has removed it accepts CSRs without it. A node that has not yet
   removed it still waits for it. Either way is safe.
3. Never remove nodes on both sides of a partition. Each side would then
   accept CSRs alone, and the two sides could accept different CSRs for one
   name.

The evicted node, if it comes back, still lists its old peers. They refuse
its leases, so it accepts no CSR.

**Adding a node D:**
1. Install D with every current node in its `SNIF_CLUSTER_PEERS`, and its
   keys on every current node. Run only `snif-syncd`: no `snif-certd`, no
   snifdog, and no address in DNS.
2. Seed D (section 7.4). The current nodes do not list D yet, so they refuse
   its writes, and D cannot accept a CSR.
3. Add D to `SNIF_CLUSTER_PEERS` on every current node, in any order. From
   then on, each node that lists D sends it every CSR it accepts. D itself
   accepts no CSR until every node lists it.
4. Reconcile D with every node again. That copies the CSRs that nodes
   accepted before they listed D.
5. Start snifd, `snif-certd` and snifdog on D, restart snifd on every other
   node one at a time so it opens D's FIFOs (section 10), and add D's
   address to DNS (section 9).

**Rejoining** an evicted node is adding it again, from step 1. It accepted
nothing while it was out, so nothing can conflict.

**Removing a node for good** is evicting it, then removing its address from
DNS and its keys from the other nodes. Its counter files stay and still count
(section 4).

## 4. CA proxy state

Every file under the CA proxy base directory belongs to one class. The sync
daemon, `snif-syncd`, carries only the synced classes. The receiving side
checks every path against these patterns before writing anything.

| Path | Written by | Class |
|---|---|---|
| `cfg/<cn>.cfg` | `snif-auth.php`, at allocation | once |
| `csr/<cn>.csr` | `snif-cert.php` | once, under the CSR lease (section 5) |
| `auth/<cn>.auth` | `snif-auth.php`, at approval | once |
| `crt/<cn>.crt` | `snif-certd` | certificate |
| `crt/<cn>.err` | `snif-certd` | newest |
| `apns/_<id>.apns` | `snif-apnsd` | newest |
| `auth/ves/<node>/<email>` | `inc/snif-auth-ves.php` | counter |
| `auth/captcha/<node>/<file>` | `inc/snif-auth-captcha.php` | counter |
| `log/`, `arc/`, `var/`, `sync-queue/`, any temp file ending in `+` | | local |
| `etc/` | the operator | local |

Rules per class:

- **once:** created if absent, never overwritten, never deleted. A receiver
  that already holds different content keeps its own and reports a conflict.
  `csr/` files travel only through the `CSR` request, never through the queue
  (section 5).
- **certificate:** the receiver keeps whichever certificate has the later
  notAfter, and its own on a tie. Installing a certificate also removes the
  local `crt/<cn>.err`, as `snif-certd` does after a successful issue.
- **newest:** the later sender modification time wins. That compares clocks,
  so it needs NTP. It is used only for these two files, which are rarely
  written.
- **counter:** each node writes only its own `<node>` directory, and a reader
  adds up every node's file, including those of removed nodes. A receiver
  accepts a counter file only from the node it names. A VES file holds one
  line per approval with its time, and the reader replays every node's
  approvals in time order through the account's leaky bucket.
- **local:** never leaves the node.
  - `arc/` is produced on every node by `snif-arc` from the `crt/`
    modification times, which the sync preserves.
  - `log/<cn>.log` holds `snif-certd`'s one-hour retry throttle, which is
    per node on purpose.

`apns/` must sync. A device sends its wake token
(`SNIF MSG <host> apns=<token>`) to the node it is connected to, and only
that node's `snif-apnsd` stores it (section 2.2). The wake is sent from the
node a client reaches, which may be any other.

Synced files keep their modification time. `snif-certd`'s one-day reissue
throttle and `snif-arc`'s 75-day archive both read it.

**`etc/`** is configuration and secrets, and the sync never carries it:

- Non-secret files (`*.domains`, `*.keyalgo`, `*.authurl`, `*.authpage`,
  `*.pub-ca`) are deployed to every node by the operator's release process.
- Secrets (`*.priv-ca`, `*.tsig`, `account.key`) are installed on each node by
  hand and backed up, never kept in a repository.

A node holding these secrets can issue for every name the cluster serves, so
the nodes form one trust domain.

**Single node:** counters move into `<node>` subdirectories only when peers
are configured. A reader also counts the existing `auth/ves/<email>` file, so
current counts carry over.

**The init origin's certificate** (for example `snif.snif.xyz`) uses **one
key shared by the nodes** (decided 2026-10-14). The name then follows the
rule every other name follows: one name, one key.
- The key is a secret, installed on each node by hand like those above.
- **The certificate is the web server's, from either of two sources:**
  - **An ACME client outside the CA proxy.** The VES relay does this
    (2026-10-25): its estate's issuer renews by the certificate's expiry,
    and the nodes send it the same CSR, made once from the shared key and
    copied with it, so each renewal is one certificate for all of them.
  - **`snif-certd`.** `etc/<origin>.domains` makes the name an origin:
    `SNIF CERT <origin>` issues that name itself, from Let's Encrypt, never
    a wildcard and never from a local CA. The operator's tooling writes
    `csr/<origin>.csr` from the shared key through `CSR` (section 7.2), as
    `snif-cert.php` does for a device, and sends `SNIF CERT` when the
    certificate is due. `snif-certd` keeps no schedule of its own, and no
    web endpoint asks, since there is no `cfg/` file for the name. The
    certificate lease means one node issues; the others get
    `crt/<origin>.crt` from the sync, and install it for their web server.
- snifdog keeps ignoring the name (`SNIFDOG_NAME_ALLOW`), in every base
  domain's configuration.

## 5. Accepting a CSR

A name's CSR fixes the one key that name will ever carry
(`security-model.md`). No two nodes may hold different CSRs for one name,
for two reasons:

- snifdog alerts on any Certificate Transparency certificate whose key
  differs from `csr/<cn>.csr` (`relay_csr_spki` and its caller). CT entries
  never go away, so neither does the alert.
- It also alerts on a certificate for a name it holds no CSR for. Every node
  must therefore hold the CSR before any node's certificate for that name can
  reach CT.

**A name that gets stuck is acceptable. A name with two different CSRs is
not.** A connector that cannot enrol starts over with a new name and key in
time. Two CSRs for one name, on different nodes, would each be issued, and
snifdog would alert on every node for good.

So the rule that must always hold is: **for every name, every node that holds
a CSR holds the same one.** Three rules keep it:

1. **Every write to `csr/` creates the file only if it is absent** (temp file,
   fsync, `link()`), on every node and by every path. An existing CSR is
   never replaced or deleted.
2. **Every write to `csr/` happens under the name's CSR lease** (section 6),
   including the copy reconciliation makes. The receiving node checks the
   lease itself, so a request that arrives after its lease has ended is
   refused.
3. **The node accepting a CSR writes to every listed peer first and to itself
   second,** and only after every one of them has answered `STORED` or `SAME`
   for the same content.

With peers configured, `snif-cert.php` passes the PUT body to the local
`snif-syncd` (`CSR`, section 7.2), which:

1. takes the CSR lease for the name (section 6). If the lease is held
   elsewhere, it waits up to 5 s (**default**), then answers `BUSY`. If a
   listed peer cannot be asked, it answers `UNREACHABLE`;
2. checks the local `csr/<cn>.csr`: identical content answers `SAME`,
   different content answers `DIFFERENT`;
3. sends `CSR <cn>` to every listed peer at once. Each checks the lease,
   creates the file if it is absent, and answers `STORED`, `SAME`,
   `DIFFERENT` or `REJECT`;
4. if every peer answered `STORED` or `SAME`, and only while its own view of
   the lease is still valid, creates the local file. If any answered
   `DIFFERENT`, it answers `DIFFERENT`. Otherwise it answers `UNREACHABLE` and
   creates nothing;
5. releases the lease.

`snif-cert.php` maps the answers to HTTP:
- `STORED` or `SAME`: 201.
- `DIFFERENT`: 403.
- `BUSY`, `UNREACHABLE`, `REJECT` or any error: 503.

One change from today: an identical repeated PUT gets 201 rather than 403.

When something fails:

- **A listed peer cannot be reached:** the lease is not taken, nothing is
  stored anywhere, and no new device can enrol through this node. Existing
  devices and renewals carry on.
- **Some peers' answers are lost or missing:** this node answers 503 and
  writes nothing. Some peers may hold the CSR, and reconciliation later
  copies it to the rest, so every node holds the same content and the name
  is stuck.
- **This node's 201 to the connector is lost:** the name is stuck in the same
  way.

A stuck name resolves on the connector's side. `snif_cert_pkey` in
`lib/cert.c` makes a new key after any answer other than 201, and the
connector takes a new name when it starts over.

**The first certificate for a name** is issued only once every listed peer
holds the same CSR.
- `snif-certd` asks the daemon to make sure (`ENSURE`, section 7.2). Under
  the CSR lease, the daemon sends the CSR to every listed peer, and each
  answers `STORED` or `SAME`.
- If any of them cannot be asked, the first certificate waits.
- A node that already holds a certificate for the name, in `crt/` or `arc/`,
  renews without asking.

This keeps every node's snifdog from seeing a certificate for a name it has
no CSR for.

## 6. Leases

There are two leases per name:

| Lease | Guards | Duration (**default**) | If a peer cannot be asked |
|---|---|---|---|
| `csr:<cn>` | every write to `csr/<cn>.csr` | 30 s | not taken, so nothing is written |
| `crt:<cn>` | issuing a certificate | 600 s | taken without it (`ALONE`), for renewals only |

The CSR lease is what prevents two CSRs for one name. The certificate lease
only saves duplicate issues.

- **Taking a lease:** `LEASE <name> <seconds>` to every listed peer at once.
  A peer answers `GRANTED` unless it holds that lease, has granted it to
  another node, or is requesting it itself and wins the tie; then it answers
  `HELD`. The lease is held only with `GRANTED` from every listed peer.
- **Tie (default):** when two nodes request the same lease at the same
  moment, the lower node name wins. A node that grants a lease it is
  requesting gives up its own request, and gives back any grants it already
  got for it.
- **A partial grant is given back.** A node that gets `HELD` from any peer
  sends `RELEASE` to the peers that granted, and tries again after a random
  delay of up to 1 s (**default**), within the 5 s wait. With three or more
  nodes, simultaneous requests can all fail this way. The random delay
  separates them on the next try.
- **Why no two nodes hold one lease:** two nodes that list each other each
  need the other's grant, and a node never grants a lease it holds, has
  granted, or is requesting and wins. Two nodes that list a common peer both
  need its grant, and it grants to one at a time. Section 3.2 keeps one of
  the two true for every pair.
- **The granting node records the grant,** with an expiry measured on its own
  clock from the moment it granted. While the grant lasts:
  - it does not take that lease itself, nor grant it to another node;
  - it accepts the writes that lease covers (`CSR` for a CSR lease) only from
    the holder, and refuses them from anyone at any other time.

  A restart forgets every grant, so the restarted node refuses such writes
  until the holder takes the lease again. That errs on the safe side.
- **The holder's own view ends first.** It counts the duration from the moment
  it sent its first request, minus a margin (**default** 5 s), and checks it
  before every write it makes. No timestamp crosses between nodes. Only the
  rate of the clocks matters, and real clocks agree on rate far more closely
  than that margin needs.
- **A late request is harmless.** Say a node's `CSR` request arrives after
  that node gave up and closed the session (section 3.1). Either the grant is
  still running, in which case the peer cannot have accepted another CSR for
  the name from anyone. Or it has ended, and the peer refuses the request.
- **Release:** `RELEASE <name>` when done. A holder that dies, or loses its
  session, just lets the grant run out. Locally, a lease also ends when the
  process that asked for it closes its connection to the daemon.
- **The certificate lease:** `snif-certd` holds it while issuing, and gives up
  an issue that runs past the duration.
  - 600 s covers the longest issue: up to 120 s waiting for every nameserver
    to serve the challenge (`$DNSWait`), plus the ACME round trips.
  - Before issuing, it fetches the peers' certificates (`FETCH crt/<cn>.crt`)
    and applies its usual throttle. A fresh certificate from any peer means
    nothing is issued.
- **Peers unreachable, certificate lease:** with `GRANTED` from every peer it
  can reach, and at least one it cannot, renewals go ahead (`ALONE`). Any
  `HELD` means `HELD`.
  - Every node holds the same CSR, so every node would sign the same key.
    snifdog treats that as a renewal.
  - Since `5fcba31`, DNS-01 challenge values are added rather than replaced,
    so concurrent challenges do not break each other.
  - The cost is one Let's Encrypt duplicate certificate per group of nodes
    that cannot reach each other, once per renewal.

  First certificates wait (section 5). `snif-certd` treats a local daemon that
  does not answer the same way.

## 7. snif-syncd

One daemon per node, written in Perl like `snif-certd` and `snif-apnsd`, and
running as the CA proxy user. It is not started when no peers are configured.

### 7.1 The queue

When a component has put a synced file in its final place, it creates a
symlink for each listed peer, `sync-queue/<peer>/<path>`, pointing at the
file. Then it pings the daemon. The daemon sends the file and removes the link
once the peer has the file on disk. `csr/` never goes through the queue
(section 5).

- **Enqueue** after the final rename. If the link already exists (`EEXIST`),
  the file is already queued. The ping (`SYNC` on the local socket) only wakes
  the daemon, so a lost ping costs time, not data.
- **Claim before sending:** the daemon renames the entry into
  `sync-queue/<peer>/.inflight/<path>` before it reads the file. A write
  during the send creates a fresh entry, which is sent next. Without the claim,
  removing the entry after the acknowledgement would also discard the entry
  for a newer version.
- **The path comes from the entry's place under `sync-queue/<peer>/`,** never
  from the link target. Both sides check it against the class patterns
  (section 4) and reject `..` and anything else. That is what keeps `etc/` and
  every secret out of the channel.
- **A dangling entry** (the file is gone) is dropped and logged, never turned
  into a deletion. Nothing synced is ever deleted.
- **A node sends only the files written on it,** and never passes on a file
  it received. A file whose writer stopped before reaching every peer spreads
  through reconciliation (section 7.4).
- **After a restart or a reconnect,** entries in `.inflight/` go back into the
  queue.
- **Scans:** the daemon also scans the queue on startup and every 60 s
  (**default**). That catches a lost ping and a writer that never pinged.
- **Health:** the age of the oldest entry per peer (the symlink's own
  modification time) shows whether that link works. `snif-syncd status`
  prints it, and the daemon logs when it passes a threshold (**default**
  300 s).

### 7.2 Local interface

Unix socket `var/snif-syncd.sock`, one request per line:

| Request | Reply | Used by |
|---|---|---|
| `SYNC` | none | every writer, after enqueuing |
| `CSR <cn> <size> <sha256>` + body | `STORED`, `SAME`, `DIFFERENT`, `BUSY`, `UNREACHABLE` | `snif-cert.php` |
| `ENSURE <cn>` | `STORED`, `SAME`, `DIFFERENT`, `UNREACHABLE` | `snif-certd`, before a first certificate |
| `LEASE <cn>` | `GRANTED`, `ALONE`, `HELD` | `snif-certd` (the certificate lease) |
| `RELEASE <cn>` | `OK` | `snif-certd` |
| `FETCH <path>` | `FOUND`, `NONE`, `UNREACHABLE` | `snif-cert.php`, `snif-auth.php`, `snif-certd` |
| `STATUS` | lines ending with `END` | `snif-syncd status` |
| `RECONCILE [<peer>]` | `OK pulled=… pushed=… conflicts=… failed=…` | `snif-syncd reconcile`, daily |
| `SEED <peer>` | the same | `snif-syncd seed`, for a new node (section 3.2) |
| `PEER <node>` | none: the rest of the connection is that peer's session | `snif-syncd --serve <node>` |

The CSR lease is taken and released inside the daemon. A certificate lease
lasts until `RELEASE` or until the connection that took it closes. `ENSURE`
for a name with no local CSR answers `UNREACHABLE`.

`snif-syncd --serve <node>`, the forced command of a peer's key, only
connects to the local socket, sends `PEER <node>`, and relays bytes both ways.
So one process holds every lease, grant and queue, and the relay holds no
state. `SNIF_CLUSTER_PEER_CMD` sets the command for outgoing sessions (`%n`
this node, `%p` the peer, `%a` its address); the default is the ssh command
of section 3. `ca-proxy/test/syncd.t` replaces it with a local `--serve`
against another tree, and runs three nodes on one host.

`FETCH` asks every listed peer it can reach with `GET`, installs what it gets
under the file's class rule, and then answers:
- `FOUND` when any peer had the file;
- `NONE` when every listed peer answered that it has none;
- `UNREACHABLE` when no peer had it and at least one could not be asked.

### 7.3 Peer protocol

On the sync session (section 3), one request per line and one reply each:

| Request | Reply |
|---|---|
| `HELLO <node> <version>` | `HELLO <node> <version>` |
| `PING` | `PONG` |
| `PUT <path> <size> <mtime> <sha256>` + body | `OK`, `KEPT`, `REJECT <reason>` |
| `CSR <cn> <size> <sha256>` + body | `STORED`, `SAME`, `DIFFERENT`, `REJECT lease`, `REJECT member` |
| `LEASE <name> <seconds>` | `GRANTED`, `HELD`, `REJECT member` |
| `RELEASE <name>` | `OK` |
| `GET <path>` | `DATA <size> <mtime> <sha256>` + body, or `NONE` |
| `LIST <class>` | one `<path> <size> <mtime> <sha256>` line per file, then `END` |

`PUT` refuses every `csr/` path, and refuses a node it does not list
(`REJECT member`). `CSR` is accepted only from the current holder of the
name's CSR lease.

Writing on the receiving side, for `PUT` and `CSR`:
1. Write a temp file in the target directory and fsync it.
2. Set the sender's modification time.
3. Apply the class rule: `link()` for create-if-absent, `rename()` for
   replace.
4. Only then answer.

`KEPT` means the receiver kept its own copy: an existing once-file, or a
certificate with a later expiry. `KEPT` on a once-file whose content differs
is a conflict: it is logged and shown by `status`.

Requests on the path of a client's HTTP request (`CSR`, `LEASE`, `GET` for a
`FETCH`) go ahead of queued `PUT`s.

### 7.4 Reconciliation and seeding

`snif-syncd reconcile` runs daily and on demand. It goes through every listed
peer in turn, exchanging `LIST` both ways.
- Anything missing on one side, or older there, is queued.
- A missing CSR is copied with the `CSR` request under the CSR lease, never
  with `PUT`.
- A once-file whose content differs between the two sides is a conflict and
  is never overwritten. For `csr/` it should be impossible (section 5). If it
  happens, it is reported, and no certificate is issued for that name.

Since every pair of nodes reconciles, a file reaches every node within a day,
even when the node that wrote it is gone.

**Seeding a new node:** before it starts snifdog or `snif-certd`, and before
it appears in DNS, it copies one node's whole `csr/`, plus `cfg/`, `auth/`,
`crt/` and `apns/`, then reconciles with every other node. `csr/` holds every
CSR ever accepted, and it is snifdog's record of the right key for each name.
Without it, the new node's snifdog reports every renewal of an existing
device as never provisioned. Section 3.2 gives the order of the steps around
seeding.

## 8. Changes to existing components

**Status:** all built (2026-10-15) and on master, except the optional
`snifd/fifo.c` check.

The CA proxy components know they are on a cluster node from
`etc/cluster.node`, which holds the node's name. It is a static file on
purpose: with `snif-syncd` stopped, a cluster node must still know it is one,
and refuse CSRs (503) rather than accept them alone. A writer queues a file
with a link in every `sync-queue/<peer>/`; `snif-syncd` keeps those
directories equal to its listed peers, so queuing needs no running daemon.
`ca-proxy/inc/snif-cluster.php` holds the PHP side of this.

| Component | Change |
|---|---|
| `ca-proxy/public_html/snif-cert.php` | Send PUT through `CSR` (section 5); identical repeat gives 201; when `cfg/<cn>.cfg` is missing, `FETCH` it before answering, 404 on `NONE` and 503 on `UNREACHABLE` |
| `ca-proxy/secure_html/snif-auth.php` | Enqueue `cfg/` and `auth/` files; `FETCH` a missing cfg before refusing; `FETCH` a missing `auth/` before approving again |
| `ca-proxy/inc/snif-auth-ves.php`, `snif-auth-captcha.php` | Per-node counter files, added up on read; enqueue |
| `ca-proxy/bin/snif-certd` | `ENSURE` before a first certificate; take the certificate lease and `FETCH` the peers' certificates before issuing; give up past the lease duration; drop the `unlink` before the `rename` of a new certificate; enqueue `crt/` and `.err`; find the challenge record by following the alias of `_acme-challenge.<name>`; send each DNS-01 update to every nameserver of that zone with a timeout, wait on those that answered it, and retry failed removals (section 9) |
| `ca-proxy/bin/snif-apnsd` | Write tokens to a temp file and rename (today it rewrites the file in place); enqueue |
| `ca-proxy/bin/snif-arc` | None; it runs on each node |
| `ca-proxy/mkdirs` | For each listed peer, `sync-queue/<peer>/` and the FIFO pair; can run again after the peers change. The ca-proxy install runs it |
| `ca-proxy/bin/snif-relay`, `etc/snif.conf` | New settings `SNIF_CLUSTER_NODE`, `SNIF_CLUSTER_PEERS` (each peer's node name and address), `SNIF_CLUSTER_LEASE`; `SNIF_RELAY_SRV` names this node. `snif-relay` itself needs no change |
| `snifd/fifo.c`, `snifd/host.c`, `snifd/ctl.c` | Hold a `CONNECT` for a host with no control connection here; drop it on `CLEAR`, `CLOSE` or the client timeout, with a cap; `snif_ctl_sethost` sends the held lines (section 2.1). Optional: drop a `CONNECT` from an input FIFO that names an unknown service address |
| `snifd/sock.c` | A connect timeout per address in `snif_sock_connect` (**default** 5 s), instead of a blocking connect (section 9) |
| snifdog | One config per base domain, in `/etc/snif/snifdog.d/`; the cron job runs a `snifdog poll` pass for every config in the directory. A config there defaults its state directory to `/var/lib/snif/snifdog/<base>`, and a pass takes a lock on its state directory, since today nothing stops two passes sharing state. The existing `/etc/snif/snifdog.conf` keeps working as before. It runs on each node |
| New | `ca-proxy/bin/snif-syncd` and its unit; `ca-proxy/inc/snif-cluster.php`; `ca-proxy/bin/snif-tunnel <peer>` and the template unit `snif-tunnel@<peer>.service`, one instance per peer |
| Tests | `snifd/test/held.sh`, `snifd/test/conntmout.sh`, `ca-proxy/test/syncd.t` (three nodes), `ca-proxy/test/cluster.t` (two nodes end to end, with the PHP and a local CA), and new cases in `certd-dns.t` and `apnsd.t` |

About the `unlink` in `snif-certd`: `getcert` deletes the old certificate and
then renames the new one into place. The rename alone replaces the old one in
a single step, and without the delete there is no moment in which a GET finds
no certificate.

## 9. DNS

Only the DNS-01 challenge values change while the cluster runs. The nodes'
addresses are static: every node's address is published, and a client that
cannot reach one tries the next. So the worst a DNS failure can cause is a
refused validation, which `snif-certd` retries.

- **The pool name gets its own zone,** `snif-pool.<base>` of one base domain,
  delegated from its parent.
  - It holds the nodes' addresses, which are static, and the challenge values,
    which are dynamic.
  - Every `_acme-challenge.<device>.<base>` reaches it through the wildcard
    alias.
  - The parent changes only when a node is added or removed. The parent's
    existing records at the pool name (today an A record and the challenge
    TXT records) move into the new zone.
- **Several base domains share it.** Each base's wildcard points at the same
  pool name (`*.<other base> CNAME snif-pool.<base>`), so every base's
  challenge values land in one record set. That causes no conflict:
  - an ACME challenge value is unique to its authorization, so no two
    attempts write the same value;
  - each `snif-certd` removes only the values it added (since `5fcba31`);
  - the only cost is the record set's size, about 60 bytes per value in
    flight.
- **The zone is mastered independently on two nameservers in different
  regions,** however many nodes there are.
  - Each holds its own copy. Neither transfers from the other, and neither
    sends NOTIFY.
  - The static part is identical on both, and is edited on both when a node
    is added or removed.
  - Each accepts dynamic updates with one key, limited to the TXT records at
    the pool name.
  - Losing either region leaves a writable copy.
- **`snif-certd` writes every challenge value to every nameserver of the pool
  zone,** each with a timeout (**default** 5 s).
  - It finds where to write by following the alias of
    `_acme-challenge.<name>`, not from the name's base domain. So a base that
    points at the shared pool name needs nothing else. If the alias cannot be
    followed, it writes `snif-pool.<base>` in the zone `<base>`, as before.
  - It signs with `etc/<base>.tsig`, as today. Every base that shares the
    pool holds the pool zone's key there.
  - It goes ahead when at least one server accepted the value.
  - It then waits until every server that answered the update serves the
    value, for up to `$DNSWait`. One that refused may be a secondary, which
    gets the value by zone transfer. A server that did not answer is not
    waited for.
  - It removes values from every server that accepted them. A removal that
    fails is kept in `var/snif-certd.pending` and tried again after later
    attempts, for up to 7 days, so stale values do not pile up.
- **A nameserver that answers but refuses updates,** and never serves the
  value, fails the issue after `$DNSWait`, before Let's Encrypt is asked.
  `snif-certd` retries after its one-hour throttle.
- **The failure that remains:** a nameserver that did not answer the update
  but answers queries.
  - Let's Encrypt validates from several vantage points, and each may ask
    either server, so the order then usually fails.
  - `snif-certd` retries after its one-hour throttle, which stays within
    Let's Encrypt's limit on failed validations.
  - A nameserver that is down does not cause this, because resolvers move on
    to the other server.
- **Other names:**
  - When `snif-certd` issues the init origin (section 4), its challenge
    name is an alias for the pool name too (`_acme-challenge.<init origin>
    CNAME snif-pool.<base>`). A name that exists is not covered by the
    wildcard. An ACME client outside the CA proxy needs the alias pointed at
    its own challenge record instead.
  - The wildcards of other base domains (for example a private-CA domain)
    point at the pool name for the nodes' addresses. Private-CA names need no
    challenges.
  - A zone apex, such as a site at `snif.host`, cannot be an alias, so it
    lists every node's address.

**Connectors fail over slowly today, and with static addresses that matters.**
`snif_sock_connect` (`snifd/sock.c`) tries every address of a name, but its
connect call blocks. An address that silently drops packets therefore costs
the full TCP connect timeout, about two minutes with Linux defaults, before
the next address is tried. A connect timeout per address (section 8) makes a
dead node's address cheap to skip.

`snif-certd` also waits for every nameserver today, and treats one that does
not answer as missing (`txt_served`). So a single nameserver being down fails
every issue after `$DNSWait`. Not waiting for a server that did not answer
the update fixes that.

## 10. Restarts

snifd restarts only for a configuration change or a new binary. A restart
drops every control connection and service connection on that node, and its
devices reconnect. Restart one node at a time.

snifd takes its FIFOs only at start (`ca-proxy/bin/snif-relay`). So adding a node
means restarting snifd on every other node, one at a time, to open the new
node's FIFO pair. A removed node's FIFOs can wait for the next restart: with
no reader, writes to them fail and are dropped.

`snif-certd`, `snif-apnsd` and `snif-syncd` restart when their code changes.
None of them forwards traffic. PHP needs nothing.

## 11. Failures

| Failure | Effect |
|---|---|
| A node is down | Its address stays in DNS, and clients and connectors move on to another address (section 9). Its devices reconnect to other nodes. Renewals continue (`ALONE`). New enrolments and first certificates wait on every node that lists it (section 5) |
| A node stays down | Evict it on every other node (section 3.2) |
| The network between two nodes A and B is down | Clients on A time out for devices on B, and the reverse. A and B cannot accept CSRs, and every other node still can. Files between A and B queue |
| Only a tunnel is down | As above for forwarding, in that direction. Nothing reports it, so it needs monitoring |
| Only a sync session is down | Files for that peer queue. Certificate leases are `ALONE`. CSR acceptance on the two ends answers `UNREACHABLE` |
| The cluster splits into groups that cannot reach each other | Each group serves its own devices. Clients reach only devices in their own group. No node accepts CSRs. Renewals continue in each group, at the cost of one duplicate certificate per group |
| One of the pool zone's nameservers is down | Challenge values go to the other one. Validation works, because resolvers move on to the server that answers |
| A pool zone nameserver answers but refuses updates | Issues for device names fail after `$DNSWait`, before Let's Encrypt is asked. `snif-certd` retries hourly and logs the refused update |
| `snif-syncd` is down | Enqueuing still works, since it only creates links. CSR PUTs to that node get 503. Its `snif-certd` renews as `ALONE` and holds first certificates. Other nodes cannot accept CSRs while they cannot reach it |
| `snif-certd` dies mid-issue | Its connection closes, and the lease is released |
| A node loses its disk | Rebuild it, then add it again (section 3.2) before it serves |
| Clock skew | Affects only the newest class. Leases compare durations, never timestamps |

## 12. Open questions

1. The two nameservers mastering the pool zone (section 9). For the public
   relay, these are planned on its operator's existing nameservers.
2. Defaults to confirm:
   - request deadline 3 s, heartbeat every 5 s with 3 missed,
   - CSR lease 30 s, margin 5 s, CSR wait for a held lease 5 s,
   - random retry delay up to 1 s after a partial grant,
   - certificate lease 600 s,
   - tie goes to the lower node name,
   - queue scan every 60 s, health threshold 300 s,
   - challenge update timeout 5 s per nameserver,
   - connect timeout 5 s per address,
   - at most 4096 held `CONNECT` lines per node.
3. **Enrolment needs every listed peer.** One node down pauses new
   enrolments on every node until it returns or is evicted, so pauses get
   more likely as nodes are added. A majority rule would keep enrolment going
   without a minority of nodes. But a node that missed a CSR would then see
   that name's first certificate in CT, and its snifdog would report it as
   never provisioned (section 5). Not designed.
4. No limit on the number of nodes is set. Each node writes every push once
   per peer and waits on every peer for leases, so the load per node and the
   chance of a pause both grow with the number of nodes.

## 13. Tests

A three-node setup on one host. Three is the smallest cluster in which
partial grants, a single broken link and membership changes differ from two.
- three snifd instances on different ports,
- three CA proxy trees,
- the six tunnels and six sync sessions over ssh to localhost,
- stubbed ACME and DNS, as in `ca-proxy/test`.

The tests that do not need a third node also run with two.

Forwarding:
- A client on any node reaches a device on any other.
- A service address shared by the nodes reproduces the failure (this guards
  the requirement in section 2).
- With the tunnel from B to A removed, clients on B time out for devices on
  A, and every other pair still works (this guards the complete graph).
- A device that connects to C after a client for it reached B gets the
  client's `CONNECT`, and the client is joined well within its timeout.
- A held line goes away on `CLEAR`, on `CLOSE`, and after the client timeout,
  on every node holding it. One delivered late is refused by the client's
  node, and nothing else happens.
- Past the cap, the oldest held line is dropped.
- A line from an input FIFO never appears on any output FIFO.
- A wake token stored on A reaches the `apns/` of B and C, and a client on C
  wakes the device through C's `snif-apnsd`.

CSR acceptance:
- A CSR accepted on A is on B and C before the 201. A repeated PUT gets 201.
  A different CSR on C gets 403.
- With one node down, a PUT on any other node gets 503, and no node stores
  anything.
- With only the network between A and B down, C accepts, and A and B answer
  503.
- Different CSRs PUT for one name on all three nodes at once: at most one is
  accepted, and every node ends up holding it or nothing.
- **A late `CSR` request** (delayed past its deadline, arriving after another
  node has started its own accept for the name) is refused, and no split
  results.
- A lost reply leaves the CSR on some nodes. Reconciliation copies it to the
  rest under the lease, and the name is stuck, not split.
- After a restart of a granting node, a `CSR` request from the old holder is
  refused.
- A node that is not listed gets `REJECT member` for `CSR`, `LEASE` and
  `PUT`, and answers to `GET` and `LIST`.

Leases:
- Three nodes requesting one lease at once: never two holders, partial grants
  are given back, and one node gets the lease within the wait.
- A grant whose `RELEASE` was lost runs out at its expiry.

Issuing:
- A first certificate waits while any listed peer is unreachable. A renewal
  proceeds as `ALONE`.
- Concurrent issues on every node: one issues, and the others install the
  fetched certificate.
- Split into two groups: one issue per group, and both groups hold a
  certificate for the same key.
- `snif-certd` killed mid-issue releases the lease.

Liveness:
- The heartbeat marks a stopped peer down within 15 s, and requests are then
  answered at once.

Membership:
- Eviction on every other node: they accept without it, and the evicted node
  keeps refusing.
- Eviction done on one node but not yet on another: the first accepts, the
  second waits, and no split results.
- A fourth node added as in section 3.2: it accepts no CSR before every node
  lists it, and its snifdog stays quiet afterwards.

The queue:
- A file rewritten during a send: the newest version arrives.
- A dangling entry is dropped.
- `.inflight/` is recovered after a restart.
- An entry pointing into `etc/`, or containing `..`, is refused by both sides.
- A `PUT` for a `csr/` path is refused.
- A file whose writer stopped after sending it to one peer reaches the third
  node at the next reconciliation.

The data rules:
- Approvals on every node add up against the per-account cap.
- The later certificate wins on every node, and the `.err` file is cleared.
- Modification times survive the sync, and `snif-arc` archives a certificate
  on every node on the same day.

DNS:
- A challenge value is written to both nameservers, and removed from both.
- A device under a second base domain gets its challenge through the shared
  pool name, and a concurrent issue under the first base is not disturbed.
- With one nameserver down, the update times out there, and the issue
  succeeds.
- With one nameserver answering but refusing updates, the issue fails, and
  is retried after the throttle.
- A removal that failed is retried on the next run.
- A connector whose first address silently drops packets reaches another
  node within the connect timeout.

Recovery:
- A tunnel killed: the unit restarts it, and the health check shows the gap.

Single node:
- With no peers configured, behaviour is identical to today, and the existing
  tests pass.
