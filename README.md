# Specter

A tiny obfuscated TCP relay protocol: a Go server plus a Python SOCKS5 client.
Point any SOCKS-capable app (v2ray, browsers, curl) at the local client and it
rides to the server inside Specter's framing.

> **Warning:** Specter is *obfuscation*, not audited cryptography. The keystream
> is SHA-256 in counter mode and the handshake tag is HMAC-SHA-256/128 — fine
> for dodging naive DPI, **not** for protecting secrets from a motivated
> adversary. Use WireGuard / Trojan for anything sensitive.

## Layout

```
specter/
├── server/      # Go relay server (no dependencies, stdlib only)
│   ├── main.go
│   └── go.mod
├── client/      # Python SOCKS5 client (stdlib only)
│   └── client.py
└── README.md
```

## How it works

```
app → SOCKS5 127.0.0.1:10867 → [Specter/TCP] → server → target
```

1. The app makes a normal SOCKS5 `CONNECT` (IPv4 / domain / IPv6) to the client.
2. The client opens TCP to the server and performs the Specter handshake,
   then streams both directions as encrypted frames.
3. The server verifies the handshake, dials the target, and relays.

## Wire format (v1)

All integers big-endian. `PSK` is a 32-byte pre-shared key (both sides).

### Handshake (client → server, 36 bytes + address)

| Field   | Size | Value                                              |
|---------|------|----------------------------------------------------|
| `MAGIC` | 4    | `52 31 07 9d` (`R1\x07\x9d`)                       |
| nonce   | 16   | random per connection                              |
| tag     | 16   | `HMAC-SHA256(PSK, MAGIC \|\| nonce)[0:16]`         |

Then the target address, SOCKS5-style:

| atyp | Address that follows              |
|------|-----------------------------------|
| 0x01 | 4-byte IPv4                       |
| 0x03 | 1-byte length + domain bytes      |
| 0x04 | 16-byte IPv6                      |

then 2-byte port. The server `compare_digest`s the tag; on mismatch it
closes silently (no banner, no error — just like a filtered port).

### Frames (both directions)

```
+--------+--------------+
| len:u16| payload      |
+--------+--------------+
```

`len` is the encrypted payload length in the clear (`1..16383`).
Payload is XORed with a per-direction keystream:

```
keystream(nonce, dir, ctr) = SHA256(PSK || nonce || dir || BE32(ctr))
dir = 0x00 client→server, 0x01 server→client; ctr counts 32-byte blocks from 0
```

Each direction has an independent stream/counter starting at 0 for the
connection nonce. No padding, no MAC on frames (the handshake tag is the
only authentication) — again: obfuscation, not a secure channel.

## Run the server

```bash
export SPECTER_PSK="$(openssl rand -hex 32)"   # 64 hex chars, keep secret!
export SPECTER_LISTEN="0.0.0.0:43117"          # optional
go build -o specter-server ./server
./specter-server
```

## Run the client

```bash
cp client/config.example.json client/config.json
# edit client/config.json: server, port, psk (64 hex chars from server)
python3 client/client.py
# or: python3 client/client.py path/to/myconfig.json
# SOCKS5 now on 127.0.0.1:10867
```

Env vars (`SPECTER_SERVER` / `SPECTER_PORT` / `SPECTER_PSK`) override
config.json if you prefer those. `client/config.json` is git-ignored so
your key never gets committed.

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
