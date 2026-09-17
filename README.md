# Specter

A tiny obfuscated TCP/UDP relay protocol: a Go server plus Go and Python
SOCKS5 clients. Point any SOCKS-capable app (v2ray, browsers, curl) at the
local client and it rides to the server inside Specter's framing.

**Downloads:** see [Releases](https://github.com/IntellsGamer/specter/releases)
— `specter-client-*` for Windows/macOS/Linux, `specter-server-linux-*`.
Run the client once and it writes a dummy `config.json` next to itself
(with a popup when a display is present) — fill in your server details.


> **Warning:** Specter has real forward secrecy (X25519 + HKDF per
> connection) and authenticated frames, but it is NOT independently audited.
> Use WireGuard / Trojan for anything that needs a certified guarantee.

## Layout

```
specter/
├── server/      # Go relay server (stdlib + x/crypto only)
│   ├── main.go
│   ├── go.mod / go.sum
│   └── config.example.json
├── client/      # Python SOCKS5 client (stdlib only, optional `cryptography` accel)
│   ├── client.py
│   └── config.example.json
└── README.md
```

## How it works

```
app → SOCKS5 127.0.0.1:10867 → [Specter/TCP or /UDP] → server → target
```

1. The app makes a normal SOCKS5 `CONNECT` (IPv4 / domain / IPv6) to the client.
2. The client opens a Specter session (TCP handshake or first UDP datagram),
   then streams both directions as authenticated fixed-size records.
3. The server verifies, dials the target, and relays.

## Wire format (v3)

All integers big-endian. `PSK` is a 32-byte long-term key used **only** as
HMAC salt and HKDF salt — never directly for encryption. Per-connection
session key: `sk = HKDF-SHA256(shared, salt=PSK, info="specter-v3")` where
`shared = X25519(client_eph, server_eph)`. Stealing the PSK later does not
decrypt past sessions (both ephemerals are discarded afterwards).

### Handshake

Client → server (69 bytes):

| Field   | Size | Value                                              |
|---------|------|----------------------------------------------------|
| ver     | 1    | `0x02` (anything else → silent close)              |
| magic   | 4    | fresh random bytes, every connection               |
| nonce   | 16   | fresh random bytes (replay cache, 10 min window)   |
| ephC    | 32   | client ephemeral X25519 public key                 |
| tag     | 16   | `HMAC-SHA256(PSK, ver \|\| magic \|\| nonce \|\| ephC)[0:16]` |

Server → client (49 bytes): `ver \|\| ephS(32) \|\|
HMAC-SHA256(PSK, ver \|\| ephS \|\| ephC \|\| nonce)[0:16]`.
The client verifies this — a MITM without the PSK cannot complete the
handshake. Both sides then derive the same `sk` and forget the ephemerals.

### TCP cells (fixed 1024 bytes)

```
+-------------+------------------------------------------+
| rnonce : 12 | AEAD(sk, rnonce, pt) : 996 + 16 tag       |
+-------------+------------------------------------------+
pt = dlen u16 || data (≤994) || random pad to 996
```

Fresh random nonce per cell, no counters to desync. First cell's data is
`atyp+addr+port` (SOCKS5 encoding); the rest carry stream bytes.

### UDP datagrams (fixed 1280 bytes)

First datagram of a session (fixed 1280 B):

```
ver(1) magic(4) nonceC(16) ephC(32) tag(16) sid(8) seq(4) flags(1)=0x01
  + AEAD(sk0, nonce=nonceC[:12], AD=sid||flags||seq, pt)   # pt: atyp+addr+port+pad
```

`sk0 = SHA256(PSK || "specter-v3-hs" || nonceC)` protects only this hello
(the FS key doesn't exist yet). The server dials the target immediately
and answers with a fixed 1280 B reply:

```
sid(8) ephS(32) tagS(16) + random pad
tagS = HMAC-SHA256(PSK, ver || ephS || ephC || nonceC || sid)[0:16]
```

The client retransmits the hello until the reply arrives (8 s), verifies
`tagS`, derives `sk`, and starts data. Retransmitted hellos get the reply
re-sent (idempotent).

Later datagrams:

```
sid(8) rnonce(12) flags(1) seq u32(4) + AEAD(sk, rnonce, AD=sid||flags||seq, pt)
  # pt = dlen u16 || data (≤1237) || pad; total always 1280
```

`sid` is a random 8-byte session id (target sent once, never again).
Per-datagram keys/nonces make loss and reorder harmless to crypto;
a 64-deep reorder buffer with 300–500 ms gap-skip keeps streams flowing.
Server sessions roam across client IPs and expire after 120 s idle.

## Run the server

```bash
export SPECTER_PSK="$(openssl rand -hex 32)"   # 64 hex chars, keep secret!
export SPECTER_LISTEN="0.0.0.0:43117"          # optional, TCP+UDP same port
export SPECTER_TRANSPORT=udp                   # tcp = TCP only, else TCP+UDP
go build -o specter-server ./server
./specter-server
```

## Run the client

Two clients, same `client/config.json`, same SOCKS5 on `127.0.0.1:10867`:

```bash
cp client/config.example.json client/config.json
# edit client/config.json: server, port, psk, transport ("tcp" or "udp")
```

**Go client (fast — ~540 MB/s AEAD, use this):**

```bash
# Windows: download client-go/specter-client.exe from the repo, put it
# next to your config.json, double-click (or: specter-client.exe config.json)
# Linux:
go build -o specter-client ./client-go && ./specter-client [config.json]
```

**Python client (legacy, portable, slower):** `client/client.py` — same
protocol and config, kept for platforms without a Go build. Uses
`cryptography` (~68 MB/s) if installed, else a pure-Python fallback
(~0.5 MB/s — browsing only).

```bash
python3 client/client.py
# or: python3 client/client.py path/to/myconfig.json
```

Env vars (`SPECTER_SERVER` / `SPECTER_PORT` / `SPECTER_PSK` /
`SPECTER_TRANSPORT`) override config.json. `client/config.json` is
git-ignored so your key never gets committed.

v2ray outbound example:

```json
{ "protocol": "socks", "settings": { "servers": [{ "address": "127.0.0.1", "port": 10867 }] } }
```

## Why it looks the way it does

- **TCP, not QUIC** — survives networks that fingerprint and drop QUIC.
- **Silent close on bad tag** — scanners see a dead port, not an error.
- **Fixed-size records** — 1024 B cells / 1280 B datagrams; lengths and
  padding hide inside the AEAD.
- **Small static binaries / one Python file** — almost no dependencies to rot.

## License

MIT — do what you want, don't blame us.

## Transport modes

| Mode  | Config                | Wire                       | Use case                      |
|-------|-----------------------|----------------------------|-------------------------------|
| `tcp` | `"transport":"tcp"`  | 1024 B AEAD cells          | Direct path. Fastest when clean. |
| `udp` | `"transport":"udp"`  | 1280 B AEAD datagrams      | Independent of TCP order/retransmit; tries a different path treatment by DPI. |

UDP is selected client-side by the config value. The server serves the
mode(s) it is started with: `SPECTER_TRANSPORT=tcp` → TCP only, anything
else → TCP+UDP on the same port. **Both ends must agree** — a `udp` client
against a TCP-only server stalls silently (by design).

## Multiplexing (v3.4, TCP legs)

One TCP trunk carries many SOCKS streams; the per-connection handshake
happens once per trunk instead of once per tab.

| Client `mux` | Server `SPECTER_MUX` | Result |
|---|---|---|
| `off` | either | Legacy single-stream (pre-mux behavior) |
| `on` | `on` (default) | Mux trunk, fails closed otherwise |
| `on` | `off` | Refused, client logs and fails the connection |
| `on` | — | `transport=udp` refused: mux needs a TCP leg |
| `auto` (default) | `on` | Trunk, transparent fallback to legacy |
| `auto` | `off` / old server | Legacy single-stream |

Negotiation is the handshake version byte (`0x03` legacy, `0x04` mux);
crypto is identical, so old clients and `mux=off` work against new
servers and vice versa. UDP legs stay single-stream. `SPECTER_MUX`
overrides `config.json` on the client.

## Reliability notes (v3.4, wire-compatible)

- Target dials race all resolved addresses (250ms stagger, first wins),
  fixing slow tails when the first address is dead. IPv6 dialing fixed
  as a side effect (proper host:port joining).
- UDP first flight is selectively acked: the server sends cumulative +
  SACK ACKs (only to clients advertising support), the client resends
  unacked leading datagrams for ~3s. Kills the hung-connection case on
  slow dials, at no cost to old peers.

## Observability (v3.3+, wire unchanged — v3.3 servers work with v3.2 clients)

Both binaries log to stderr. `SPECTER_LOG=error|warn|info|debug`
(default `warn`). Nothing secret (no keys) is ever logged.

- Client access log (always on, console):
  `from 127.0.0.1:21834 accepted //github.com:443 [socks -> proxy]`
  — one line per SOCKS connection with source and target.
- `warn` (default): target dial failures and slow dials (`>2s`) with the
  target host — this is where user-visible `-1`s and spikes come from;
  client handshake failures with hints (`wrong PSK?`, `UDP blocked?`);
  drops at the connection cap.
- `info`: 5-minute counters summary
  (`tcp_accept/drop/hs_ok/hs_reject/dial_fail/dial_slow`,
  `udp_hello_ok/hello_reject/dial_fail/dial_slow/done`,
  `orphan_drained/expired`). `SPECTER_STATS_SEC` overrides the interval
  (min 5, for tests).
- `debug`: handshake rejects, hello retries/dups, relay ends, orphan
  drains. Scanner/probe noise in these categories is rate-limited
  (1 line / 5 s + suppressed count), so the port still looks dead
  while you keep signal.

## SOCKS reply semantics (read this if a client shows odd errors)

For latency, the client answers SOCKS5 success **before** the Specter
handshake to the server completes (TCP) or concurrently with it (auto
race) — the browser pipelines its first bytes while the tunnel is still
being established. Consequence: **SOCKS success means "accepted locally",
not "tunnel is up".** If the handshake then fails (wrong PSK, server
down, both transports lost), the connection is closed right after the
success reply. Browsers absorb this as a reset and retry; scripted
clients may surface it confusingly (`curl: (52) Empty reply`,
`connection reset`) — check the client log (`SPECTER_LOG=warn` names the
cause) rather than the exit code.
