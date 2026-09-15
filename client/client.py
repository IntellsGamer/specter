#!/usr/bin/env python3
"""Specter client: SOCKS5 on 127.0.0.1:10867 -> Specter protocol -> server.
Point v2ray outbound (socks) at 127.0.0.1:10867.

Configure (first found wins for each value):
  1. config.json next to this file (copy config.example.json), or
     pass a path:  python3 client.py myconfig.json
  2. env vars: SPECTER_SERVER / SPECTER_PORT / SPECTER_PSK

Toy obfuscation, NOT audited crypto."""
import hashlib
import hmac
import json
import os
import socket
import struct
import sys
import threading
import time

DEFAULT_PORT = 43117


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
    if not server or server in ("YOUR_SERVER_IP", "REPLACE_ME"):
        raise SystemExit(
            "Specter: no server set. Copy client/config.example.json to\n"
            "client/config.json and fill in server/port/psk — or set\n"
            "SPECTER_SERVER / SPECTER_PORT / SPECTER_PSK env vars."
        )
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise SystemExit("Specter: port must be a number.")
    if not raw or "REPLACE" in str(raw):
        raise SystemExit("Specter: no key set (config.json psk or SPECTER_PSK).")
    try:
        key = bytes.fromhex(str(raw).strip())
    except ValueError:
        raise SystemExit("Specter: psk is not valid hex (need 64 hex chars).")
    if len(key) != 32:
        raise SystemExit("Specter: psk must decode to exactly 32 bytes.")
    return server, port, key, transport


SERVER, SPORT, PSK, TRANSPORT = _load_config()
MAGIC = b"R1\x07\x9d"
MAXFRAME = 16383


def _ks(nonce, direction, counter):
    return hashlib.sha256(PSK + nonce + bytes((direction,)) + struct.pack(">I", counter)).digest()


class XorStream:
    def __init__(self, nonce, direction):
        self.nonce = nonce
        self.dir = direction
        self.ctr = 0
        self.buf = b""

    def run(self, data):
        out = bytearray()
        off = 0
        n = len(data)
        while off < n:
            if not self.buf:
                self.buf = _ks(self.nonce, self.dir, self.ctr)
                self.ctr += 1
            take = min(len(self.buf), n - off)
            out += bytes(c ^ k for c, k in zip(data[off:off + take], self.buf))
            self.buf = self.buf[take:]
            off += take
        return bytes(out)


def recvn(s, n):
    b = b""
    while len(b) < n:
        ch = s.recv(n - len(b))
        if not ch:
            raise EOFError
        b += ch
    return b


def relay_plain_to_framed(src, dst, enc):
    try:
        while True:
            data = src.recv(16383)
            if not data:
                break
            blob = enc.run(data)
            dst.sendall(struct.pack(">H", len(blob)) + blob)
    except (OSError, EOFError):
        pass


def relay_framed_to_plain(src, dst, dec):
    try:
        while True:
            ln = struct.unpack(">H", recvn(src, 2))[0]
            if ln == 0 or ln > MAXFRAME:
                break
            dst.sendall(dec.run(recvn(src, ln)))
    except (OSError, EOFError):
        pass


UDP_CHUNK = 1200
UDP_REORDER_MAX = 64
UDP_GAP_WAIT = 0.3


def _ks_u(nonce, direction, seq, blk):
    return hashlib.sha256(
        PSK + nonce + bytes((direction,)) + struct.pack(">I", seq) + struct.pack(">I", blk)
    ).digest()


def crypt_u(nonce, direction, seq, data):
    out = bytearray()
    blk = 0
    off = 0
    while off < len(data):
        ks = _ks_u(nonce, direction, seq, blk)
        blk += 1
        take = min(len(ks), len(data) - off)
        out += bytes(c ^ k for c, k in zip(data[off:off + take], ks))
        off += take
    return bytes(out)


def udp_leg(app, atyp, addr, port):
    """Relay one SOCKS connection over UDP datagrams to the server."""
    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        us.settimeout(30)
        us.connect((SERVER, SPORT))
    except OSError:
        us.close()
        return
    nonce = os.urandom(16)
    tag = hmac.new(PSK, MAGIC + nonce, hashlib.sha256).digest()[:16]
    header = MAGIC + nonce + tag
    target = bytes((atyp,)) + addr + port
    dead = threading.Event()

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
                blob = crypt_u(nonce, 0, seq, data)
                us.sendall(header + struct.pack(">I", seq) + target
                           + struct.pack(">H", len(blob)) + blob)
                seq += 1
        finally:
            dead.set()

    try:
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
            if len(dg) < 4 + 16 + 4 + 2 or dg[:4] != MAGIC:
                continue
            if dg[4:20] != nonce:
                continue
            seq = struct.unpack(">I", dg[20:24])[0]
            flen = struct.unpack(">H", dg[24:26])[0]
            if len(dg) < 26 + flen:
                continue
            if seq < expect or seq in pending:
                continue
            if len(pending) < UDP_REORDER_MAX:
                pending[seq] = crypt_u(nonce, 1, seq, dg[26:26 + flen])
            drained = False
            while expect in pending:
                try:
                    app.sendall(pending.pop(expect))
                except OSError:
                    dead.set()
                    break
                expect += 1
                drained = True
            if drained or expect in pending:
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
        nonce = os.urandom(16)
        tag = hmac.new(PSK, MAGIC + nonce, hashlib.sha256).digest()[:16]
        upstream = socket.create_connection((SERVER, SPORT), timeout=10)
        upstream.sendall(MAGIC + nonce + tag + bytes((atyp,)) + addr + port)
        app.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        up, down = XorStream(nonce, 0), XorStream(nonce, 1)
        t = threading.Thread(target=relay_framed_to_plain, args=(upstream, app, down), daemon=True)
        t.start()
        relay_plain_to_framed(app, upstream, up)
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


def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 10867))
    srv.listen(64)
    print("socks5 on 127.0.0.1:10867 -> %s:%d [%s]" % (SERVER, SPORT, TRANSPORT), flush=True)
    while True:
        app, _ = srv.accept()
        threading.Thread(target=handle, args=(app,), daemon=True).start()


if __name__ == "__main__":
    main()
