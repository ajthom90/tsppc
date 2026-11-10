#!/usr/bin/env python3
"""Generate the TLS trust anchors (ISRG Root X1 and X2) and their test fixture.

Standard library only. The outputs are committed, so building the project
never needs Python or network access:

    python3 -I tools/gen_anchors.py src/net/anchors.c tests/anchors_der.inc

By default the PEMs are fetched from letsencrypt.org. With --pem-dir DIR they
are read from DIR/isrgrootx1.pem and DIR/isrg-root-x2.pem instead.

Each certificate's SHA-256 fingerprint must equal the value pinned below, so a
re-run cannot silently change a root. The pinned values were checked against
the macOS system root store. A changed pin needs review.

anchors.c holds, per root, the encoded subject DN and the public key in
BearSSL's br_x509_trust_anchor form, plus ts_build_time: midnight UTC on the
day it was generated, a date a correct clock can never precede. The fixture
holds the full DER of each certificate (test builds only), so a test can check
that BearSSL's own decoder agrees with what this script extracted.
"""
import argparse
import base64
import datetime
import hashlib
import os
import sys
import urllib.request

ROOTS = [
    {
        "name": "ISRG Root X1",
        "file": "isrgrootx1.pem",
        "url": "https://letsencrypt.org/certs/isrgrootx1.pem",
        "sha256": "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6",
    },
    {
        "name": "ISRG Root X2",
        "file": "isrg-root-x2.pem",
        "url": "https://letsencrypt.org/certs/isrg-root-x2.pem",
        "sha256": "69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470",
    },
]

OID_RSA = "1.2.840.113549.1.1.1"
OID_EC = "1.2.840.10045.2.1"
# BearSSL curve identifiers (BR_EC_*), as in TLS.
CURVES = {
    "1.2.840.10045.3.1.7": ("BR_EC_secp256r1", 65),
    "1.3.132.0.34": ("BR_EC_secp384r1", 97),
    "1.3.132.0.35": ("BR_EC_secp521r1", 133),
}


def fail(msg):
    sys.stderr.write("gen_anchors: %s\n" % msg)
    sys.exit(1)


def tlv(buf, pos):
    """Return (tag, start of contents, end of contents) of the DER element at pos."""
    if pos + 2 > len(buf):
        fail("truncated DER")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        fail("multi-byte tag")
    n = buf[pos + 1]
    pos += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or pos + k > len(buf):
            fail("bad DER length")
        n = int.from_bytes(buf[pos:pos + k], "big")
        pos += k
    if pos + n > len(buf):
        fail("DER element overruns its container")
    return tag, pos, pos + n


def children(buf, start, end):
    out = []
    pos = start
    while pos < end:
        tag, s, e = tlv(buf, pos)
        if e > end:
            fail("DER child overruns its parent")
        out.append((tag, pos, s, e))
        pos = e
    return out


def oid_str(b):
    first = b[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    v = 0
    for c in b[1:]:
        v = (v << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(v)
            v = 0
    return ".".join(str(p) for p in parts)


def uint_bytes(b):
    """A DER INTEGER's contents as an unsigned big-endian value, no leading zeros."""
    if not b or b[0] & 0x80:
        fail("negative or empty INTEGER")
    b = b.lstrip(b"\x00")
    return b if b else b"\x00"


def extract(der):
    """Return (subject DN DER, key) where key is ('rsa', n, e) or ('ec', curve, q)."""
    tag, s, e = tlv(der, 0)
    if tag != 0x30 or e != len(der):
        fail("certificate is not one SEQUENCE")
    cert = children(der, s, e)
    if len(cert) != 3 or cert[0][0] != 0x30:
        fail("certificate does not have tbs, algorithm, signature")
    tbs = children(der, cert[0][2], cert[0][3])
    i = 1 if tbs[0][0] == 0xA0 else 0     # optional [0] version
    # serial, signature algorithm, issuer, validity, subject, subjectPublicKeyInfo
    if len(tbs) < i + 6:
        fail("short TBSCertificate")
    subj = tbs[i + 4]
    spki = tbs[i + 5]
    if subj[0] != 0x30 or spki[0] != 0x30:
        fail("subject or key info is not a SEQUENCE")
    dn = der[subj[1]:subj[3]]                 # whole Name, tag and length included
    alg, bits = children(der, spki[2], spki[3])
    algp = children(der, alg[2], alg[3])
    if algp[0][0] != 0x06 or bits[0] != 0x03:
        fail("bad SubjectPublicKeyInfo")
    oid = oid_str(der[algp[0][2]:algp[0][3]])
    if der[bits[2]] != 0:
        fail("public key BIT STRING has unused bits")
    key = der[bits[2] + 1:bits[3]]
    if oid == OID_RSA:
        t, ks, ke = tlv(key, 0)
        parts = children(key, ks, ke)
        if t != 0x30 or len(parts) != 2 or parts[0][0] != 2 or parts[1][0] != 2:
            fail("bad RSAPublicKey")
        n = uint_bytes(key[parts[0][2]:parts[0][3]])
        ex = uint_bytes(key[parts[1][2]:parts[1][3]])
        return dn, ("rsa", n, ex)
    if oid == OID_EC:
        if len(algp) != 2 or algp[1][0] != 0x06:
            fail("EC key without a named curve")
        curve = oid_str(der[algp[1][2]:algp[1][3]])
        if curve not in CURVES:
            fail("unsupported curve %s" % curve)
        name, qlen = CURVES[curve]
        if len(key) != qlen or key[0] != 4:
            fail("EC point is not uncompressed or has the wrong length")
        return dn, ("ec", name, key)
    fail("unsupported key algorithm %s" % oid)


def pem_to_der(text, label):
    lines = text.strip().splitlines()
    try:
        b = lines.index("-----BEGIN CERTIFICATE-----")
        e = lines.index("-----END CERTIFICATE-----")
    except ValueError:
        fail("%s: no PEM certificate" % label)
    if b != 0 or e != len(lines) - 1:
        fail("%s: expected exactly one certificate" % label)
    return base64.b64decode("".join(lines[b + 1:e]), validate=True)


def load(root, pem_dir):
    if pem_dir:
        with open(os.path.join(pem_dir, root["file"]), "r", encoding="ascii") as f:
            text = f.read()
    else:
        with urllib.request.urlopen(root["url"], timeout=30) as r:
            text = r.read().decode("ascii")
    der = pem_to_der(text, root["name"])
    got = hashlib.sha256(der).hexdigest()
    if got != root["sha256"]:
        fail("%s: SHA-256 %s does not match the pinned %s" % (root["name"], got, root["sha256"]))
    return der


def c_bytes(b, indent="    "):
    out = []
    for i in range(0, len(b), 12):
        out.append(indent + " ".join("0x%02x," % c for c in b[i:i + 12]))
    return "\n".join(out)


def fingerprint(hexs):
    return ":".join(hexs[i:i + 2] for i in range(0, len(hexs), 2))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("anchors_c")
    ap.add_argument("fixture_inc")
    ap.add_argument("--pem-dir")
    args = ap.parse_args()

    ders = [load(r, args.pem_dir) for r in ROOTS]
    today = datetime.datetime.now(datetime.timezone.utc).date()
    built = int(datetime.datetime(today.year, today.month, today.day,
                                  tzinfo=datetime.timezone.utc).timestamp())

    head = ["/* Generated by tools/gen_anchors.py from the PEMs published at",
            " * letsencrypt.org. Do not edit. Certificate SHA-256 fingerprints:"]
    for r in ROOTS:
        head.append(" *   %s" % r["name"])
        head.append(" *     %s" % fingerprint(r["sha256"]))
    head.append(" */")

    c = list(head)
    c += ["", '#include "tls.h"', ""]
    entries = []
    for i, (r, der) in enumerate(zip(ROOTS, ders)):
        dn, key = extract(der)
        c.append("/* %s */" % r["name"])
        c.append("static const unsigned char ta%d_dn[] = {" % i)
        c.append(c_bytes(dn))
        c.append("};")
        if key[0] == "rsa":
            _, n, ex = key
            c.append("static const unsigned char ta%d_n[] = {" % i)
            c.append(c_bytes(n))
            c.append("};")
            c.append("static const unsigned char ta%d_e[] = {" % i)
            c.append(c_bytes(ex))
            c.append("};")
            entries.append(
                "    { { (unsigned char *)ta%d_dn, sizeof ta%d_dn }, BR_X509_TA_CA,\n"
                "      { BR_KEYTYPE_RSA, { .rsa = { (unsigned char *)ta%d_n, sizeof ta%d_n,\n"
                "                                   (unsigned char *)ta%d_e, sizeof ta%d_e } } } }"
                % (i, i, i, i, i, i))
        else:
            _, curve, q = key
            c.append("static const unsigned char ta%d_q[] = {" % i)
            c.append(c_bytes(q))
            c.append("};")
            entries.append(
                "    { { (unsigned char *)ta%d_dn, sizeof ta%d_dn }, BR_X509_TA_CA,\n"
                "      { BR_KEYTYPE_EC, { .ec = { %s, (unsigned char *)ta%d_q, sizeof ta%d_q } } } }"
                % (i, i, curve, i, i))
        c.append("")
    c.append("const br_x509_trust_anchor ts_anchors[TS_ANCHOR_COUNT] = {")
    c.append(",\n".join(entries))
    c.append("};")
    c.append("")
    c.append("/* Midnight UTC on %s, the day this file was generated. */" % today.isoformat())
    c.append("const time_t ts_build_time = %d;" % built)

    f = list(head)
    f += ["", "/* Test fixture: the full certificates, in the order of ts_anchors. */"]
    for i, (r, der) in enumerate(zip(ROOTS, ders)):
        f.append("static const unsigned char anchor_der%d[] = {" % i)
        f.append(c_bytes(der))
        f.append("};")

    if len(ROOTS) != 2:
        fail("tls.h's TS_ANCHOR_COUNT assumes two roots")
    with open(args.anchors_c, "w", encoding="ascii") as out:
        out.write("\n".join(c) + "\n")
    with open(args.fixture_inc, "w", encoding="ascii") as out:
        out.write("\n".join(f) + "\n")
    for r in ROOTS:
        print("%s SHA-256 %s" % (r["name"], fingerprint(r["sha256"])))


if __name__ == "__main__":
    main()
