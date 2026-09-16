"""Pure-Python X25519 (RFC 7748) + HKDF-SHA256. No dependencies."""
import hashlib
import hmac as _hmac

P = 2 ** 255 - 19
A24 = 121665


def _clamp(k: bytes) -> int:
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(bytes(b), "little")


def x25519(priv32: bytes, pub32: bytes) -> bytes:
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
        A = (x2 + z2) % P
        AA = (A * A) % P
        B = (x2 - z2) % P
        BB = (B * B) % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x3 = pow((DA + CB) % P, 2, P)
        z3 = (x1 * pow((DA - CB) % P, 2, P)) % P
        x2 = (AA * BB) % P
        z2 = (E * ((AA + A24 * E) % P)) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, P - 2, P)) % P).to_bytes(32, "little")


BASE = (9).to_bytes(32, "little")


def pubkey(priv32: bytes) -> bytes:
    return x25519(priv32, BASE)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, out_len: int = 32) -> bytes:
    prk = _hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    for i in range(1, (out_len + 31) // 32 + 1):
        t = _hmac.new(prk, t + info + bytes((i,)), hashlib.sha256).digest()
        out += t
    return out[:out_len]


if __name__ == "__main__":
    import sys
    # cross-check mode: print pub/shared for a given privkey (hex argv)
    if len(sys.argv) > 1:
        priv = bytes.fromhex(sys.argv[1])
        print("pub=" + pubkey(priv).hex())
        raise SystemExit
    import time
    # regression: verified against Go x/crypto + cryptography lib
    A = bytes.fromhex("9fab709cbc634b19a931403d9a9f9089fbb575fd8cc11fc5a99535fae5d40863")
    B = bytes.fromhex("1854eb23a7da6f2b0e5a6ce4982c77bac950ea9e24ab85df826363d77265c178")
    assert pubkey(A).hex() == "242660a6d14da178f3afaffeffd9564ee4425de4e1156688b96889428272d328"
    assert pubkey(B).hex() == "b1ee398689090925c2cb10af1a9059ac82adc02614e74efd1567c5b1875fa14d"
    S = x25519(A, pubkey(B))
    assert S.hex() == "f0930e78ead68822f83065e56d596eae2cd4827524796d3040f789e5e539294d"
    assert x25519(B, pubkey(A)) == S, "ECDH symmetry"
    assert hkdf_sha256(S, b"SALT-TEST", b"specter-v3").hex() == \
        "c430aa345912272bad608a788dd81d3e4f93e6ba411526f27a8104e637f4b0a3"
    print("x25519+hkdf vectors: PASS")
    t0 = time.time()
    for _ in range(3):
        x25519(A, pubkey(B))
    print("x25519 scalar mult: %.0f ms/op" % ((time.time() - t0) / 3 * 1000))
