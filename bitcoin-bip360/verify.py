# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

import json
import os
import subprocess
import sys
import tempfile

RAW_PK = {"ML-DSA-44": 1312, "SLH-DSA-SHA2-128s": 32}
HERE = os.path.dirname(os.path.abspath(__file__))


def spki(raw, scheme):
    der = subprocess.run(["openssl", "genpkey", "-algorithm", scheme, "-outform", "DER"],
                         capture_output=True).stdout
    pub = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                         input=der, capture_output=True).stdout
    return pub[:len(pub) - RAW_PK[scheme]] + raw


def verify(scheme, raw_pk, msg, sig):
    der = spki(raw_pk, scheme)
    with tempfile.NamedTemporaryFile(delete=False) as fk:
        fk.write(der)
        kp = fk.name
    with tempfile.NamedTemporaryFile(delete=False) as fm:
        fm.write(msg)
        mp = fm.name
    with tempfile.NamedTemporaryFile(delete=False) as fs:
        fs.write(sig)
        sp = fs.name
    r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", kp,
                        "-keyform", "DER", "-rawin", "-in", mp, "-sigfile", sp],
                       capture_output=True)
    for x in (kp, mp, sp):
        os.unlink(x)
    return r.returncode == 0


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "vectors.json")
    data = json.load(open(path))
    ok = bad = 0
    for o in data:
        want = o["expected"] == "valid"
        got = verify(o["scheme"], bytes.fromhex(o["public_key"]),
                     bytes.fromhex(o["message"]), bytes.fromhex(o["signature"]))
        mark = "ok" if got == want else "MISMATCH"
        if got == want:
            ok += 1
        else:
            bad += 1
        print(f"{mark:8} want={o['expected']:6} got={'valid' if got else 'reject':6} {o['scheme']} {o['name']}")
    print(f"\npassed {ok} failed {bad}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
