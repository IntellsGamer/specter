#!/usr/bin/env python3
"""Specter v2 client (Python, LEGACY — prefer the Go client in ../client-go):
SOCKS5 on 127.0.0.1:10867 -> Specter AEAD protocol.
Config: config.json next to this file (see config.example.json), or
  python3 client.py other.json. Env SPECTER_SERVER/PORT/PSK/TRANSPORT override.
AEAD: uses `cryptography` lib if installed, else embedded pure-Python fallback.
Not audited crypto; toy obfuscation with real authentication."""
import hashlib
import hmac
import json
import os
import socket
import struct
import sys
import threading
import time

VERSION = 0x02
DEFAULT_PORT = 43117
CELL = 1024
CELL_PT = 996
CELL_DATA = 994
DGRAM = 1280
DGRAM_PT = 1239
DGRAM_DATA = 1237
FIRST_PT = 1182
UDP_CHUNK = 1200
UDP_REORDER_MAX = 64
UDP_GAP_WAIT = 0.3


def _load_config():
    cfg = {}
    arg_path = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else None
    candidates = [arg_path] if arg_path else []
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json"))
    for path in candidates:
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    cfg = json.load(f)
            except (OSError, ValueError):
                raise SystemExit("Specter: cannot parse %s (must be valid JSON)." % path)
            break
    server = os.environ.get("SPECTER_SERVER") or cfg.get("server", "")
    port = os.environ.get("SPECTER_PORT") or cfg.get("port", DEFAULT_PORT)
    transport = (os.environ.get("SPECTER_TRANSPORT") or cfg.get("transport", "tcp")).lower()
    if transport not in ("tcp", "udp"):
        raise SystemExit('Specter: transport must be "tcp" or "udp".')
    raw = os.environ.get("SPECTER_PSK") or cfg.get("psk", "")
    if (not server or server in ("YOUR_SERVER_IP", "REPLACE_ME")
            or not raw or "REPLACE" in str(raw)):
        _first_run(candidates)
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise SystemExit("Specter: port must be a number.")
    try:
        key = bytes.fromhex(str(raw).strip())
    except ValueError:
        raise SystemExit("Specter: psk is not valid hex (need 64 hex chars).")
    if len(key) != 32:
        raise SystemExit("Specter: psk must decode to exactly 32 bytes.")
    return server, port, key, transport


def _notify(title, msg):
    """GUI popup when a display exists, else stderr."""
    import sys as _sys
    try:
        if os.name == "nt":
            import ctypes as _ct
            _ct.windll.user32.MessageBoxW(0, msg, title, 0x40)
            return
        if _sys.platform == "darwin":
            import subprocess as _sp
            _sp.run(["osascript", "-e",
                     'display dialog "%s" with title "%s" buttons {"OK"}' % (msg, title)],
                    timeout=30)
            return
        if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
            import shutil as _sh, subprocess as _sp
            if _sh.which("zenity"):
                _sp.run(["zenity", "--info", "--title=" + title, "--text=" + msg],
                        timeout=30)
                return
    except Exception:
        pass
    print("%s: %s" % (title, msg))


def _first_run(candidates):
    """Write a dummy config.json (never overwrite) + explain, then exit."""
    target = None
    for path in candidates:
        if path:
            target = path
            break
    if target and not os.path.exists(target):
        try:
            with open(target, "w", encoding="utf-8") as f:
                json.dump({"server": "203.0.113.10", "port": DEFAULT_PORT,
                           "transport": "tcp",
                           "psk": "REPLACE_WITH_64_HEX_CHARS_FROM_SERVER"}, f, indent=2)
            os.chmod(target, 0o600)
        except OSError:
            target = None
    msg = ("I wrote a dummy config.json%s — fill in server/port/psk "
           "and run me again." % (" at " + target if target else ""))
    _notify("Specter", msg)
    raise SystemExit("Specter: " + msg)


SERVER, SPORT, PSK, TRANSPORT = _load_config()


# ---------- AEAD (fast lib if present, else pure Python) ----------

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as _C20P
    from cryptography.exceptions import InvalidTag as _InvalidTag

    def aead_seal(sk, nonce, pt, aad):
        return _C20P(sk).encrypt(nonce, pt, aad if aad else None)

    def aead_open(sk, nonce, ct, aad):
        try:
            return _C20P(sk).decrypt(nonce, ct, aad if aad else None)
        except _InvalidTag:
            raise ValueError("bad tag")

    AEAD_IMPL = "cryptography"
except ImportError:
    def _rotl(v, n):
        return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

    def _qr(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] ^= x[a]; x[d] = _rotl(x[d], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] ^= x[c]; x[b] = _rotl(x[b], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] ^= x[a]; x[d] = _rotl(x[d], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] ^= x[c]; x[b] = _rotl(x[b], 7)

    def _block(key, nonce12, ctr):
        st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
        st += list(struct.unpack("<8I", key)) + [ctr & 0xFFFFFFFF]
        st += list(struct.unpack("<3I", nonce12))
        w = st[:]
        for _ in range(10):
            _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13)
            _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
            _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12)
            _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
        return struct.pack("<16I", *[((a + b) & 0xFFFFFFFF) for a, b in zip(st, w)])

    def _xor(key, nonce12, data, ctr=1):
        out = bytearray()
        while data:
            ks = _block(key, nonce12, ctr)
            ctr += 1
            n = min(len(ks), len(data))
            out += bytes(a ^ b for a, b in zip(data[:n], ks))
            data = data[n:]
        return bytes(out)

    _P130 = (1 << 130) - 5

    def _mac(msg, key32):
        r = int.from_bytes(key32[:16], "little") & 0xFFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
        s = int.from_bytes(key32[16:], "little")
        acc = 0
        for i in range(0, len(msg), 16):
            blk = msg[i:i + 16]
            acc = ((acc + (int.from_bytes(blk, "little") + (1 << (8 * len(blk))))) * r) % _P130
        return ((acc + s) % (1 << 128)).to_bytes(16, "little")

    def _pad16(m):
        return m + (b"\x00" * (-len(m) % 16))

    def aead_seal(sk, nonce, pt, aad):
        ct = _xor(sk, nonce, pt, 1)
        m = _pad16(aad) + _pad16(ct) + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct))
        return ct + _mac(m, _block(sk, nonce, 0)[:32])

    def aead_open(sk, nonce, blob, aad):
        ct, tag = blob[:-16], blob[-16:]
        m = _pad16(aad) + _pad16(ct) + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct))
        if not hmac.compare_digest(_mac(m, _block(sk, nonce, 0)[:32]), tag):
            raise ValueError("bad tag")
        return _xor(sk, nonce, ct, 1)

    AEAD_IMPL = "pure-python"


_P25519 = 2 ** 255 - 19
_A24 = 121665


def _clamp(k):
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(bytes(b), "little")


def x25519(priv32, pub32):
    k = _clamp(priv32)
    u = int.from_bytes(pub32, "little")
    x1, x2, z2, x3, z3 = u, 1, 0, u, 1
    swap = 0
    for t in range(255, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        A = (x2 + z2) % _P25519
        AA = (A * A) % _P25519
        B = (x2 - z2) % _P25519
        BB = (B * B) % _P25519
        E = (AA - BB) % _P25519
        C = (x3 + z3) % _P25519
        D = (x3 - z3) % _P25519
        DA = (D * A) % _P25519
        CB = (C * B) % _P25519
        x3 = pow((DA + CB) % _P25519, 2, _P25519)
        z3 = (x1 * pow((DA - CB) % _P25519, 2, _P25519)) % _P25519
        x2 = (AA * BB) % _P25519
        z2 = (E * ((AA + _A24 * E) % _P25519)) % _P25519
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, _P25519 - 2, _P25519)) % _P25519).to_bytes(32, "little")


_XBASE = (9).to_bytes(32, "little")


def x25519_pub(priv32):
    return x25519(priv32, _XBASE)


def hkdf_sha256(ikm, salt, info, out_len=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    for i in range(1, (out_len + 31) // 32 + 1):
        t = hmac.new(prk, t + info + bytes((i,)), hashlib.sha256).digest()
        out += t
    return out[:out_len]


def fs_key(shared):
    return hkdf_sha256(shared, PSK, b"specter-v3")


def hs_key(hs_nonce):
    return hashlib.sha256(PSK + b"specter-v3-hs" + hs_nonce).digest()


def recvn(s, n):
    b = b""
    while len(b) < n:
        ch = s.recv(n - len(b))
        if not ch:
            raise EOFError
        b += ch
    return b


def seal_cell(sk, rnonce, data):
    data = data[:CELL_DATA]
    pt = struct.pack(">H", len(data)) + data + os.urandom(CELL_PT - 2 - len(data))
    return rnonce + aead_seal(sk, rnonce, pt, b"")


def open_cell(sk, cell):
    pt = aead_open(sk, cell[:12], cell[12:], b"")
    ln = struct.unpack(">H", pt[:2])[0]
    if ln > CELL_DATA:
        raise ValueError("bad len")
    return pt[2:2 + ln]


def relay_tcp(app, atyp, addr, port):
    upstream = None
    try:
        magic = os.urandom(4)
        nonce = os.urandom(16)
        eph_priv = os.urandom(32)
        eph_pub = x25519_pub(eph_priv)
        tag = hmac.new(PSK, bytes((VERSION,)) + magic + nonce + eph_pub,
                       hashlib.sha256).digest()[:16]
        upstream = socket.create_connection((SERVER, SPORT), timeout=10)
        upstream.settimeout(15)
        upstream.sendall(bytes((VERSION,)) + magic + nonce + eph_pub + tag)
        rep = recvn(upstream, 49)
        if rep[0] != VERSION:
            return
        eph_s = rep[1:33]
        tag_s = hmac.new(PSK, bytes((VERSION,)) + eph_s + eph_pub + nonce,
                         hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag_s, rep[33:49]):
            return
        sk = fs_key(x25519(eph_priv, eph_s))
        upstream.settimeout(None)
        upstream.sendall(seal_cell(sk, os.urandom(12), bytes((atyp,)) + addr + port))
        app.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

        def down():
            try:
                while True:
                    yield open_cell(sk, recvn(upstream, CELL))
            except (OSError, EOFError, ValueError):
                pass

        def pump_down():
            try:
                for chunk in down():
                    app.sendall(chunk)
            except OSError:
                pass

        t = threading.Thread(target=pump_down, daemon=True)
        t.start()
        try:
            while True:
                data = app.recv(CELL_DATA)
                if not data:
                    break
                upstream.sendall(seal_cell(sk, os.urandom(12), data))
        except OSError:
            pass
    except (OSError, EOFError):
        pass
    finally:
        try:
            app.close()
        except OSError:
            pass
        if upstream is not None:
            try:
                upstream.close()
            except OSError:
                pass


def udp_leg(app, atyp, addr, port):
    """Relay one SOCKS connection over fixed-size AEAD UDP datagrams."""
    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        us.settimeout(30)
        us.connect((SERVER, SPORT))
    except OSError:
        us.close()
        return
    magic = os.urandom(4)
    hs_nonce = os.urandom(16)
    eph_priv = os.urandom(32)
    eph_pub = x25519_pub(eph_priv)
    tag = hmac.new(PSK, bytes((VERSION,)) + magic + hs_nonce + eph_pub,
                   hashlib.sha256).digest()[:16]
    sk0 = hs_key(hs_nonce)
    sid = os.urandom(8)
    target = bytes((atyp,)) + addr + port
    dead = threading.Event()
    sk_box = {}

    def first_datagram():
        pt = target + os.urandom(FIRST_PT - len(target))
        ad = sid + b"\x01" + struct.pack(">I", 0)
        ct = aead_seal(sk0, hs_nonce[:12], pt, ad)
        return (bytes((VERSION,)) + magic + hs_nonce + eph_pub + tag + sid
                + struct.pack(">I", 0) + b"\x01" + ct)

    def data_datagram(seq, data):
        sk = sk_box["sk"]
        data = data[:DGRAM_DATA]
        pt = struct.pack(">H", len(data)) + data + os.urandom(DGRAM_PT - 2 - len(data))
        rnonce = os.urandom(12)
        ad = sid + b"\x00" + struct.pack(">I", seq)
        ct = aead_seal(sk, rnonce, pt, ad)
        return sid + rnonce + b"\x00" + struct.pack(">I", seq) + ct

    def sender():
        seq = 0
        try:
            while not dead.is_set():
                try:
                    data = app.recv(UDP_CHUNK)
                except OSError:
                    break
                if not data:
                    break
                us.sendall(data_datagram(seq, data))
                seq += 1
        finally:
            dead.set()

    def parse_reply(dg, sk):
        if len(dg) != DGRAM or dg[:8] != sid:
            return None
        rnonce, flags = dg[8:20], dg[20:21]
        seq = struct.unpack(">I", dg[21:25])[0]
        try:
            pt = aead_open(sk, rnonce, dg[25:], dg[:8] + flags + dg[21:25])
        except ValueError:
            return None
        ln = struct.unpack(">H", pt[:2])[0]
        if ln > DGRAM_DATA:
            return None
        return seq, pt[2:2 + ln]

    try:
        # hello + wait for server reply (retransmit hello, fresh session if needed)
        sk = None
        start = time.monotonic()
        us.settimeout(1)
        hello = first_datagram()
        while time.monotonic() - start < 8:
            try:
                us.sendall(hello)
            except OSError:
                return
            try:
                dg, _ = us.recvfrom(2048)
            except socket.timeout:
                continue
            if len(dg) != DGRAM or dg[:8] != sid:
                continue
            eph_s, tag_s = dg[8:40], dg[40:56]
            want = hmac.new(PSK, bytes((VERSION,)) + eph_s + eph_pub
                            + hs_nonce + sid, hashlib.sha256).digest()[:16]
            if not hmac.compare_digest(want, tag_s):
                continue
            sk = fs_key(x25519(eph_priv, eph_s))
            break
        if sk is None:
            return
        sk_box["sk"] = sk
        us.settimeout(30)
        app.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        t = threading.Thread(target=sender, daemon=True)
        t.start()
        expect = 0
        pending = {}
        gap_since = None
        while not dead.is_set():
            try:
                dg, _ = us.recvfrom(2048)
            except socket.timeout:
                break
            parsed = parse_reply(dg, sk)
            if parsed is None:
                continue
            seq, data = parsed
            if seq < expect or seq in pending:
                continue
            if len(pending) < UDP_REORDER_MAX:
                pending[seq] = data
            drained = False
            while expect in pending:
                try:
                    app.sendall(pending.pop(expect))
                except OSError:
                    dead.set()
                    break
                expect += 1
                drained = True
            if drained:
                gap_since = None
            elif pending:
                if gap_since is None:
                    gap_since = time.monotonic()
                elif time.monotonic() - gap_since > UDP_GAP_WAIT:
                    expect = min(pending)
                    gap_since = None
    finally:
        dead.set()
        try:
            us.close()
        except OSError:
            pass


def handle(app):
    upstream = None
    try:
        if recvn(app, 1) != b"\x05":
            return
        nmethods = recvn(app, 1)[0]
        methods = recvn(app, nmethods)
        if b"\x00" not in methods:
            app.sendall(b"\x05\xff")
            return
        app.sendall(b"\x05\x00")
        req = recvn(app, 4)
        ver, cmd, _, atyp = req
        if ver != 5 or cmd != 1:
            app.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        if atyp == 1:
            addr = recvn(app, 4)
        elif atyp == 3:
            ln = recvn(app, 1)[0]
            addr = bytes((ln,)) + recvn(app, ln)
        elif atyp == 4:
            addr = recvn(app, 16)
        else:
            app.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        port = recvn(app, 2)
        if TRANSPORT == "udp":
            udp_leg(app, atyp, addr, port)
            return
        relay_tcp(app, atyp, addr, port)
    except (OSError, EOFError):
        pass
    finally:
        if TRANSPORT != "udp":
            try:
                app.close()
            except OSError:
                pass


def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 10867))
    srv.listen(64)
    print("specter v3 [%s] socks5 127.0.0.1:10867 -> %s:%d (%s)"
          % (AEAD_IMPL, SERVER, SPORT, TRANSPORT), flush=True)
    while True:
        app, _ = srv.accept()
        threading.Thread(target=handle, args=(app,), daemon=True).start()


if __name__ == "__main__":
    main()
