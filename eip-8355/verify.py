# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

import json
import os
import subprocess
import sys
import tempfile

SIZES = {65: (1952, 3309), 87: (2592, 4627)}
HERE = os.path.dirname(os.path.abspath(__file__))


def spki(raw, bits):
    der = subprocess.run(["openssl", "genpkey", "-algorithm", f"ML-DSA-{bits}",
                          "-outform", "DER"], capture_output=True)
    pub = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                         input=der.stdout, capture_output=True).stdout
    PK = SIZES[bits][0]
    header = pub[:len(pub) - PK]
    return header + raw


def verify(bits, raw_pk, msg, sig):
    der = spki(raw_pk, bits)
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
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "test-vectors.json")
    data = json.load(open(path))
    ok = bad = 0
    for o in data:
        bits = 87 if "ML-DSA-87" in o["Name"] else 65
        PK, SIG = SIZES[bits]
        buf = bytes.fromhex(o["Input"])
        want = o["Expected"].endswith("01")
        if len(buf) < PK + SIG:
            got = False
        else:
            pk, sig, msg = buf[:PK], buf[PK:PK + SIG], buf[PK + SIG:]
            got = verify(bits, pk, msg, sig)
        mark = "ok" if got == want else "MISMATCH"
        if got == want:
            ok += 1
        else:
            bad += 1
        print(f"{mark:8} want={'valid' if want else 'reject':6} got={'valid' if got else 'reject':6} {o['Name']}")
    print(f"\npassed {ok} failed {bad}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
