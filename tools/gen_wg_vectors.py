#!/usr/bin/env python3
"""Generate tests/wg_vectors.inc: WireGuard handshake test vectors.

An independent implementation of the classic WireGuard handshake
(Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s, zero preshared key), written from the
WireGuard paper. It uses only the standard library and `cryptography`, and
reads or imports nothing from this repository.

Run:  python3 -I tools/gen_wg_vectors.py > tests/wg_vectors.inc

All keys are made-up test keys derived from fixed byte patterns.
"""

import hashlib
import hmac
import struct
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
LABEL_COOKIE = b"cookie--"

# Initial chaining key and hash as hard-coded by a third implementation
# (cloudflare/boringtun, noise/handshake.rs), to catch a shared misreading of
# the construction strings.
BORINGTUN_INITIAL_CK = bytes([
    96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208,
    22, 235, 66, 6, 248, 114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54])
BORINGTUN_INITIAL_H = bytes([
    34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50,
    45, 156, 108, 102, 34, 147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243])


# ---- Primitives -------------------------------------------------------------

def HASH(*parts):
    h = hashlib.blake2s()
    for p in parts:
        h.update(p)
    return h.digest()


def MAC(key, data):
    """Keyed BLAKE2s with a 16-byte digest."""
    return hashlib.blake2s(data, digest_size=16, key=key).digest()


def HMAC(key, data):
    return hmac.new(key, data, hashlib.blake2s).digest()


def KDF(n, key, data):
    prk = HMAC(key, data)
    out, prev = [], b""
    for i in range(1, n + 1):
        prev = HMAC(prk, prev + bytes([i]))
        out.append(prev)
    return out


def DH(priv, pub):
    return X25519PrivateKey.from_private_bytes(priv).exchange(
        X25519PublicKey.from_public_bytes(pub))


def PUB(priv):
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def AEAD(key, counter, pt, ad):
    nonce = b"\x00" * 4 + struct.pack("<Q", counter)
    return ChaCha20Poly1305(key).encrypt(nonce, pt, ad)


def AEAD_OPEN(key, counter, ct, ad):
    nonce = b"\x00" * 4 + struct.pack("<Q", counter)
    return ChaCha20Poly1305(key).decrypt(nonce, ct, ad)


def _rotl(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = _rotl(s[b] ^ s[c], 7)


def HCHACHA20(key, nonce16):
    s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    s += list(struct.unpack("<8I", key))
    s += list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _qr(s, 0, 4, 8, 12); _qr(s, 1, 5, 9, 13)
        _qr(s, 2, 6, 10, 14); _qr(s, 3, 7, 11, 15)
        _qr(s, 0, 5, 10, 15); _qr(s, 1, 6, 11, 12)
        _qr(s, 2, 7, 8, 13); _qr(s, 3, 4, 9, 14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def XAEAD(key, nonce24, pt, ad):
    sub = HCHACHA20(key, nonce24[:16])
    return ChaCha20Poly1305(sub).encrypt(b"\x00" * 4 + nonce24[16:], pt, ad)


def XAEAD_OPEN(key, nonce24, ct, ad):
    sub = HCHACHA20(key, nonce24[:16])
    return ChaCha20Poly1305(sub).decrypt(b"\x00" * 4 + nonce24[16:], ct, ad)


def TAI64N(sec, nsec):
    return struct.pack(">QI", 0x400000000000000a + sec, nsec & ~0xffffff & 0xffffffff)


def self_checks():
    # HChaCha20 test vector, draft-irtf-cfrg-xchacha-03 section 2.2.1.
    k = bytes(range(32))
    n = bytes.fromhex("000000090000004a0000000031415927")
    assert HCHACHA20(k, n).hex() == (
        "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
    assert HASH(CONSTRUCTION) == BORINGTUN_INITIAL_CK
    assert HASH(HASH(CONSTRUCTION), IDENTIFIER) == BORINGTUN_INITIAL_H


# ---- Handshake --------------------------------------------------------------

PSK = b"\x00" * 32


def initiation(s_i, S_r, e_i, sender, ts, cookie=None):
    """Returns (msg, state) for the initiator."""
    S_i = PUB(s_i)
    E_i = PUB(e_i)
    C = HASH(CONSTRUCTION)
    H = HASH(C, IDENTIFIER)
    H = HASH(H, S_r)
    C = KDF(1, C, E_i)[0]
    H = HASH(H, E_i)
    C, k = KDF(2, C, DH(e_i, S_r))
    enc_static = AEAD(k, 0, S_i, H)
    H = HASH(H, enc_static)
    C, k = KDF(2, C, DH(s_i, S_r))
    enc_ts = AEAD(k, 0, ts, H)
    H = HASH(H, enc_ts)
    msg = struct.pack("<I", 1) + struct.pack("<I", sender) + E_i + enc_static + enc_ts
    assert len(msg) == 116
    mac1 = MAC(HASH(LABEL_MAC1, S_r), msg)
    msg += mac1
    msg += MAC(cookie, msg) if cookie is not None else b"\x00" * 16
    assert len(msg) == 148
    return msg, dict(C=C, H=H, e=e_i, sender=sender, mac1=mac1)


def consume_initiation(s_r, msg):
    S_r = PUB(s_r)
    assert struct.unpack("<I", msg[0:4])[0] == 1
    assert MAC(HASH(LABEL_MAC1, S_r), msg[:116]) == msg[116:132]
    sender = struct.unpack("<I", msg[4:8])[0]
    E_i = msg[8:40]
    C = HASH(CONSTRUCTION)
    H = HASH(HASH(C, IDENTIFIER), S_r)
    C = KDF(1, C, E_i)[0]
    H = HASH(H, E_i)
    C, k = KDF(2, C, DH(s_r, E_i))
    S_i = AEAD_OPEN(k, 0, msg[40:88], H)
    H = HASH(H, msg[40:88])
    C, k = KDF(2, C, DH(s_r, S_i))
    ts = AEAD_OPEN(k, 0, msg[88:116], H)
    H = HASH(H, msg[88:116])
    return S_i, ts, dict(C=C, H=H, E_i=E_i, S_i=S_i, remote=sender)


def response(st, e_r, sender):
    E_r = PUB(e_r)
    C, H = st["C"], st["H"]
    C = KDF(1, C, E_r)[0]
    H = HASH(H, E_r)
    C = KDF(1, C, DH(e_r, st["E_i"]))[0]
    C = KDF(1, C, DH(e_r, st["S_i"]))[0]
    C, tau, k = KDF(3, C, PSK)
    H = HASH(H, tau)
    enc_empty = AEAD(k, 0, b"", H)
    H = HASH(H, enc_empty)
    msg = (struct.pack("<I", 2) + struct.pack("<I", sender) +
           struct.pack("<I", st["remote"]) + E_r + enc_empty)
    assert len(msg) == 60
    msg += MAC(HASH(LABEL_MAC1, st["S_i"]), msg)
    msg += b"\x00" * 16
    assert len(msg) == 92
    T_recv, T_send = KDF(2, C, b"")   # responder: first key receives
    return msg, T_send, T_recv


def consume_response(st, s_i, msg):
    S_i = PUB(s_i)
    assert struct.unpack("<I", msg[0:4])[0] == 2
    assert MAC(HASH(LABEL_MAC1, S_i), msg[:60]) == msg[60:76]
    assert struct.unpack("<I", msg[8:12])[0] == st["sender"]
    E_r = msg[12:44]
    C, H = st["C"], st["H"]
    C = KDF(1, C, E_r)[0]
    H = HASH(H, E_r)
    C = KDF(1, C, DH(st["e"], E_r))[0]
    C = KDF(1, C, DH(s_i, E_r))[0]
    C, tau, k = KDF(3, C, PSK)
    H = HASH(H, tau)
    AEAD_OPEN(k, 0, msg[44:60], H)
    T_send, T_recv = KDF(2, C, b"")   # initiator: first key sends
    return T_send, T_recv


def transport(key, receiver, counter, payload):
    pad = (-len(payload)) % 16
    return (struct.pack("<I", 4) + struct.pack("<I", receiver) +
            struct.pack("<Q", counter) + AEAD(key, counter, payload + b"\x00" * pad, b""))


def cookie_reply(S_r, receiver, nonce, cookie, last_mac1):
    msg = (struct.pack("<I", 3) + struct.pack("<I", receiver) + nonce +
           XAEAD(HASH(LABEL_COOKIE, S_r), nonce, cookie, last_mac1))
    assert len(msg) == 64
    return msg


# ---- Fixtures (made-up keys) ------------------------------------------------

def pattern(a, b):
    return bytes(((a + b * i) & 0xff) for i in range(32))


I_STATIC = pattern(0x18, 0x07)
R_STATIC = pattern(0x51, 0x0d)
I_EPH = pattern(0xa3, 0x05)
R_EPH = pattern(0x3c, 0x0b)
I_EPH2 = pattern(0x6e, 0x13)
I_INDEX = 0x11223344
R_INDEX = 0xa5b6c7d8
I_INDEX2 = 0x0badf00d
TS_SEC, TS_NSEC = 1700000000, 123456789
TS2_SEC, TS2_NSEC = 1700000005, 987654321
PAYLOAD = b"\x01\x02\x03"
COOKIE = bytes(((0xc0 + 3 * i) & 0xff) for i in range(16))
COOKIE_NONCE = bytes(((0x70 + 9 * i) & 0xff) for i in range(24))


def main():
    self_checks()
    S_i, S_r = PUB(I_STATIC), PUB(R_STATIC)
    ts = TAI64N(TS_SEC, TS_NSEC)
    ts2 = TAI64N(TS2_SEC, TS2_NSEC)

    init, ist = initiation(I_STATIC, S_r, I_EPH, I_INDEX, ts)
    got_S_i, got_ts, rst = consume_initiation(R_STATIC, init)
    assert got_S_i == S_i and got_ts == ts
    resp, r_send, r_recv = response(rst, R_EPH, R_INDEX)
    i_send, i_recv = consume_response(ist, I_STATIC, resp)
    assert i_send == r_recv and i_recv == r_send and i_send != i_recv

    data = transport(i_send, R_INDEX, 0, PAYLOAD)
    assert len(data) == 16 + 16 + 16
    assert AEAD_OPEN(r_recv, 0, data[16:], b"")[:3] == PAYLOAD

    creply = cookie_reply(S_r, I_INDEX, COOKIE_NONCE, COOKIE, ist["mac1"])
    assert XAEAD_OPEN(HASH(LABEL_COOKIE, S_r), creply[8:32], creply[32:],
                      ist["mac1"]) == COOKIE
    init2, _ = initiation(I_STATIC, S_r, I_EPH2, I_INDEX2, ts2, cookie=COOKIE)
    assert MAC(COOKIE, init2[:132]) == init2[132:]
    got_S_i, got_ts, _ = consume_initiation(R_STATIC, init2)
    assert got_S_i == S_i and got_ts == ts2

    out = sys.stdout
    out.write("/* Generated by tools/gen_wg_vectors.py (an independent Python\n"
              " * implementation of the WireGuard handshake). Do not edit.\n"
              " * All keys are made-up test keys. */\n\n")

    def hexdef(name, b):
        out.write("#define WGV_%s \\\n" % name)
        h = b.hex()
        for i in range(0, len(h), 64):
            out.write('    "%s"%s\n' % (h[i:i + 64], " \\" if i + 64 < len(h) else ""))

    def numdef(name, v):
        out.write("#define WGV_%s %s\n" % (name, v))

    hexdef("I_STATIC_PRIV", I_STATIC)
    hexdef("I_STATIC_PUB", S_i)
    hexdef("R_STATIC_PRIV", R_STATIC)
    hexdef("R_STATIC_PUB", S_r)
    hexdef("I_EPH_PRIV", I_EPH)
    hexdef("R_EPH_PRIV", R_EPH)
    hexdef("SS", DH(I_STATIC, S_r))
    numdef("I_INDEX", "0x%08xu" % I_INDEX)
    numdef("R_INDEX", "0x%08xu" % R_INDEX)
    numdef("TS_SEC", "%d" % TS_SEC)
    numdef("TS_NSEC", "%du" % TS_NSEC)
    hexdef("TAI64N", ts)
    hexdef("INIT", init)
    hexdef("RESP", resp)
    hexdef("I_SEND", i_send)
    hexdef("I_RECV", i_recv)
    hexdef("R_SEND", r_send)
    hexdef("R_RECV", r_recv)
    hexdef("PAYLOAD", PAYLOAD)
    numdef("TRANSPORT_COUNTER", "0")
    hexdef("TRANSPORT", data)
    hexdef("COOKIE", COOKIE)
    hexdef("COOKIE_REPLY", creply)
    hexdef("I_EPH2_PRIV", I_EPH2)
    numdef("I_INDEX2", "0x%08xu" % I_INDEX2)
    numdef("TS2_SEC", "%d" % TS2_SEC)
    numdef("TS2_NSEC", "%du" % TS2_NSEC)
    hexdef("TAI64N2", ts2)
    hexdef("INIT2", init2)


if __name__ == "__main__":
    main()
