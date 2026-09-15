#!/usr/bin/env python3
"""Specter client: SOCKS5 on 127.0.0.1:10867 -> Specter protocol -> server.
Point v2ray outbound (socks) at 127.0.0.1:10867.
Fill in SERVER / SPORT / PSK below, then: python3 client.py
Toy obfuscation, NOT audited crypto."""
import hashlib
import hmac
import os
import socket
import struct
import threading

SERVER = "YOUR_SERVER_IP"      # e.g. "203.0.113.10"
SPORT = 43117                  # server port


def _load_psk():
    raw = os.environ.get("SPECTER_PSK", "")
    if not raw or "REPLACE" in raw:
        raise SystemExit(
            "Specter: set your key first:\n"
            '  PowerShell:  $env:SPECTER_PSK="64_HEX_CHARS_FROM_SERVER"\n'
            "  Linux/macOS: export SPECTER_PSK=64_HEX_CHARS_FROM_SERVER\n"
            "Also edit SERVER above to your server IP."
        )
    try:
        key = bytes.fromhex(raw.strip())
    except ValueError:
        raise SystemExit("Specter: SPECTER_PSK is not valid hex (need 64 hex chars).")
    if len(key) != 32:
        raise SystemExit("Specter: SPECTER_PSK must decode to exactly 32 bytes.")
    return key


if SERVER == "YOUR_SERVER_IP":
    raise SystemExit('Specter: edit SERVER in client.py to your server IP first.')

PSK = _load_psk()
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
    print("socks5 on 127.0.0.1:10867 -> %s:%d" % (SERVER, SPORT), flush=True)
    while True:
        app, _ = srv.accept()
        threading.Thread(target=handle, args=(app,), daemon=True).start()


if __name__ == "__main__":
    main()
