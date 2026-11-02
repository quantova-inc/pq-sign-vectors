# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
RAWLEN = {"ML-DSA-44": 1312, "ML-DSA-65": 1952, "ML-DSA-87": 2592}


def read_item(b, i):
    mt = b[i] >> 5
    ai = b[i] & 31
    i += 1
    if ai < 24:
        n = ai
    elif ai == 24:
        n = b[i]; i += 1
    elif ai == 25:
        n = (b[i] << 8) | b[i + 1]; i += 2
    elif ai == 26:
        n = int.from_bytes(b[i:i + 4], "big"); i += 4
    else:
        raise ValueError("length form not used here")
    if mt in (0, 1):
        return ("int", n if mt == 0 else -1 - n), i
    if mt in (2, 3):
        v = b[i:i + n]; i += n
        return ("bytes" if mt == 2 else "text", v), i
    if mt == 4:
        items = []
        for _ in range(n):
            it, i = read_item(b, i)
            items.append(it)
        return ("array", items), i
    if mt == 5:
        pairs = []
        for _ in range(n):
            k, i = read_item(b, i)
            v, i = read_item(b, i)
            pairs.append((k, v))
        return ("map", pairs), i
    if mt == 6:
        inner, i = read_item(b, i)
        return ("tag", (n, inner)), i
    raise ValueError(mt)


def ce_uint(mt, n):
    b = mt << 5
    if n < 24:
        return bytes([b | n])
    if n < 256:
        return bytes([b | 24, n])
    if n < 65536:
        return bytes([b | 25, n >> 8, n & 255])
    raise ValueError(n)


def ce_bstr(x):
    return ce_uint(2, len(x)) + x


def ce_tstr(s):
    e = s.encode()
    return ce_uint(3, len(e)) + e


def sig_structure(protected, payload):
    return (ce_uint(4, 4) + ce_tstr("Signature1") + ce_bstr(protected)
            + ce_bstr(b"") + ce_bstr(payload))


def parse_cose_sign1(data):
    (kind, val), _ = read_item(data, 0)
    assert kind == "tag" and val[0] == 18, "not a COSE_Sign1 tag 18"
    arr = val[1]
    assert arr[0] == "array" and len(arr[1]) == 4, "COSE_Sign1 is a four element array"
    protected = arr[1][0][1]
    payload = arr[1][2][1]
    signature = arr[1][3][1]
    return protected, payload, signature


def spki(raw, scheme):
    der = subprocess.run(["openssl", "genpkey", "-algorithm", scheme, "-outform", "DER"],
                         capture_output=True).stdout
    pub = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                         input=der, capture_output=True).stdout
    return pub[:len(pub) - RAWLEN[scheme]] + raw


def verify(scheme, raw, msg, sig):
    der = spki(raw, scheme)
    f = []
    for b in (der, msg, sig):
        t = tempfile.NamedTemporaryFile(delete=False); t.write(b); t.close(); f.append(t.name)
    r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", f[0],
                        "-keyform", "DER", "-rawin", "-in", f[1], "-sigfile", f[2]],
                       capture_output=True)
    for x in f:
        os.unlink(x)
    return r.returncode == 0


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "vectors.json")
    data = json.load(open(path))
    ok = bad = 0
    for o in data:
        protected, payload, signature = parse_cose_sign1(bytes.fromhex(o["cose_sign1"]))
        msg = sig_structure(protected, payload)
        want = o["expected"] == "valid"
        got = verify(o["scheme"], bytes.fromhex(o["public_key"]), msg, signature)
        if got == want:
            ok += 1
        else:
            bad += 1
            print(f"MISMATCH want={o['expected']} got={'valid' if got else 'reject'} {o['scheme']} {o['name']}")
    print(f"passed {ok} failed {bad}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
