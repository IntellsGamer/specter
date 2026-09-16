# Specter

A tiny obfuscated TCP/UDP relay protocol: a Go server plus a Python SOCKS5 client.
Point any SOCKS-capable app (v2ray, browsers, curl) at the local client and it
rides to the server inside Specter's framing.

> **Warning:** Specter is *obfuscation with authentication*, not audited
> cryptography. Frames use ChaCha20-Poly1305 with per-connection keys, but
> there is no forward secrecy and the design has not been reviewed. Fine for
> dodging naive DPI, **not** for protecting secrets from a motivated
> adversary. Use WireGuard / Trojan for anything sensitive.

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

## Wire format (v2)

All integers big-endian. `PSK` is a 32-byte pre-shared key (both sides).
Session key: `sk = SHA256(PSK || "specter-v2-key" || hs_nonce)`.

### Handshake (client → server)

| Field   | Size | Value                                              |
|---------|------|----------------------------------------------------|
| ver     | 1    | `0x01` (anything else → silent close)              |
| magic   | 4    | fresh random bytes, every connection               |
| nonce   | 16   | fresh random bytes (replay cache, 10 min window)   |
| tag     | 16   | `HMAC-SHA256(PSK, ver \|\| magic \|\| nonce)[0:16]` |

37 bytes total over TCP; the target address travels inside the first
encrypted cell. The server drops mismatches, replays and wrong versions
silently — like a filtered port.

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

First datagram of a session:

```
ver(1) magic(4) hs_nonce(16) tag(16) sid(8) seq(4) flags(1)=0x01
  + AEAD(sk, nonce=hs_nonce[:12], AD=sid||flags||seq, pt)   # pt: atyp+addr+port+pad
```

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

```bash
cp client/config.example.json client/config.json
# edit client/config.json: server, port, psk, transport ("tcp" or "udp")
python3 client/client.py
# or: python3 client/client.py path/to/myconfig.json
# SOCKS5 now on 127.0.0.1:10867
```

Env vars (`SPECTER_SERVER` / `SPECTER_PORT` / `SPECTER_PSK` /
`SPECTER_TRANSPORT`) override config.json. `client/config.json` is
git-ignored so your key never gets committed. Install `cryptography`
(`pip install cryptography`) for ~50× faster AEAD; otherwise a pure-Python
fallback is used automatically.

v2ray outbound example:

```json
{ "protocol": "socks", "settings": { "servers": [{ "address": "127.0.0.1", "port": 10867 }] } }
```

## Why it looks the way it does

- **TCP, not QUIC** — survives networks that fingerprint and drop QUIC.
- **Silent close on bad tag** — scanners see a dead port, not an error.
- **Cleartext lengths** — trades a little metadata for a lot of speed
  (single XOR pass, no per-frame handshake).
- **One static Go binary / one Python file** — no dependencies to rot.

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
