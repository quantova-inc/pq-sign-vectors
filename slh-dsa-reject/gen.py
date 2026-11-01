# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

import json, os, subprocess, sys, tempfile

WORK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "work")
os.makedirs(WORK, exist_ok=True)

LEVEL_N = {"128": 16, "192": 24, "256": 32}
ALGS = [f"SLH-DSA-{h}-{lv}{sp}" for h in ("SHA2", "SHAKE") for lv in ("128", "192", "256") for sp in ("s", "f")]

def rawlen(alg):
    for lv, n in LEVEL_N.items():
        if f"-{lv}" in alg:
            return 2 * n
    raise ValueError(alg)

def sh_ok(args):
    r = subprocess.run(args, capture_output=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode(errors="replace")); raise SystemExit("fail " + " ".join(args))
    return r.stdout

def genkey(path, alg): sh_ok(["openssl", "genpkey", "-algorithm", alg, "-out", path])

def rawpub(sk, rl):
    der = sh_ok(["openssl", "pkey", "-in", sk, "-pubout", "-outform", "DER"])
    return der[len(der) - rl:]

def sign(sk, msg):
    with tempfile.NamedTemporaryFile(delete=False) as f: f.write(msg); mp = f.name
    sig = sh_ok(["openssl", "pkeyutl", "-sign", "-inkey", sk, "-rawin", "-in", mp]); os.unlink(mp); return sig

def spki(raw, alg, rl):
    der = sh_ok(["openssl", "genpkey", "-algorithm", alg, "-outform", "DER"])
    pub = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"], input=der, capture_output=True).stdout
    return pub[:len(pub) - rl] + raw

def verify(raw, alg, rl, msg, sig):
    der = spki(raw, alg, rl)
    f = []
    for b in (der, msg, sig):
        t = tempfile.NamedTemporaryFile(delete=False); t.write(b); t.close(); f.append(t.name)
    r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", f[0], "-keyform", "DER", "-rawin", "-in", f[1], "-sigfile", f[2]], capture_output=True)
    for x in f: os.unlink(x)
    return r.returncode == 0

def rec(alg, name, raw, msg, sig, valid):
    return dict(scheme=alg, name=name, expected=("valid" if valid else "reject"),
                public_key=raw.hex(), message=msg.hex(), signature=sig.hex())

out = []
keys = {}
for alg in ALGS:
    rl = rawlen(alg)
    sk, sk2 = f"{WORK}/{alg}.pem", f"{WORK}/{alg}.2.pem"
    genkey(sk, alg); genkey(sk2, alg)
    pk, pk2 = rawpub(sk, rl), rawpub(sk2, rl)
    keys[alg] = (pk, rl)
    msg = f"quantova-inc fips 205 {alg} reject corpus baseline".encode()
    sig = sign(sk, msg)
    assert verify(pk, alg, rl, msg, sig), f"{alg} baseline must verify"
    mid = len(sig) // 2
    sig_f0 = bytearray(sig); sig_f0[0] ^= 1; sig_f0 = bytes(sig_f0)
    sig_fm = bytearray(sig); sig_fm[mid] ^= 1; sig_fm = bytes(sig_fm)
    for tag, s in [("flip0", sig_f0), ("flipmid", sig_fm)]:
        assert not verify(pk, alg, rl, msg, s), f"{alg} {tag}"
    assert not verify(pk2, alg, rl, msg, sig), f"{alg} wrong key"
    out += [
        rec(alg, "baseline valid signature", pk, msg, sig, True),
        rec(alg, "bit flip in the first signature byte", pk, msg, sig_f0, False),
        rec(alg, "bit flip in the middle of the signature", pk, msg, sig_fm, False),
        rec(alg, "genuine signature under a different public key", pk2, msg, sig, False),
        rec(alg, "signature one byte short", pk, msg, sig[:-1], False),
        rec(alg, "signature one byte long", pk, msg, sig + b"\x00", False),
    ]

# cross hash family confusion for equal size pairs (SHA2 vs SHAKE at same level+variant)
for lv in ("128", "192", "256"):
    for sp in ("s", "f"):
        a2, ak = f"SLH-DSA-SHA2-{lv}{sp}", f"SLH-DSA-SHAKE-{lv}{sp}"
        rl = rawlen(ak)
        pk_shake = keys[ak][0]
        # sign with SHA2 key, verify under the same-size SHAKE key -> must reject
        sk_sha2 = f"{WORK}/{a2}.pem"
        msg = f"quantova-inc cross family {a2} under {ak}".encode()
        sig_sha2 = sign(sk_sha2, msg)
        assert not verify(pk_shake, ak, rl, msg, sig_sha2), f"cross {a2}->{ak}"
        out.append(rec(ak, f"cross family, a {a2} signature verified under a same size {ak} key", pk_shake, msg, sig_sha2, False))

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")
json.dump(out, open(path, "w"), indent=2)
print("wrote", path, "cases", len(out), "schemes", len(ALGS))
import collections
c = collections.Counter(o["expected"] for o in out)
print("accept", c["valid"], "reject", c["reject"])
