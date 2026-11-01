# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

import json
import os
import subprocess
import sys
import tempfile

LEVEL_N = {"128": 16, "192": 24, "256": 32}
HERE = os.path.dirname(os.path.abspath(__file__))


def rawlen(scheme):
    for lv, n in LEVEL_N.items():
        if f"-{lv}" in scheme:
            return 2 * n
    raise ValueError(scheme)


def spki(raw, scheme):
    der = subprocess.run(["openssl", "genpkey", "-algorithm", scheme, "-outform", "DER"],
                         capture_output=True).stdout
    pub = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                         input=der, capture_output=True).stdout
    return pub[:len(pub) - rawlen(scheme)] + raw


def verify(scheme, raw, msg, sig):
    der = spki(raw, scheme)
    f = []
    for b in (der, msg, sig):
        t = tempfile.NamedTemporaryFile(delete=False)
        t.write(b)
        t.close()
        f.append(t.name)
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
        want = o["expected"] == "valid"
        got = verify(o["scheme"], bytes.fromhex(o["public_key"]),
                     bytes.fromhex(o["message"]), bytes.fromhex(o["signature"]))
        if got == want:
            ok += 1
        else:
            bad += 1
            print(f"MISMATCH want={o['expected']} got={'valid' if got else 'reject'} {o['scheme']} {o['name']}")
    print(f"passed {ok} failed {bad}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
