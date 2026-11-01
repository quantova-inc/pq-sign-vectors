# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

import json, os, subprocess, sys, tempfile

WORK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "work")
os.makedirs(WORK, exist_ok=True)

ML44 = dict(alg="ML-DSA-44", PK=1312, SIG=2420, ctilde=32, zlen=2304, omega=80)
SLH = dict(alg="SLH-DSA-SHA2-128s", PK=32, SIG=7856)

def sh_ok(args):
    r = subprocess.run(args, capture_output=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode(errors="replace")); raise SystemExit("fail " + " ".join(args))
    return r.stdout

def genkey(path, alg): sh_ok(["openssl", "genpkey", "-algorithm", alg, "-out", path])

def rawpub(sk, PK):
    der = sh_ok(["openssl", "pkey", "-in", sk, "-pubout", "-outform", "DER"])
    return der[len(der) - PK:]

def sign(sk, msg):
    with tempfile.NamedTemporaryFile(delete=False) as f: f.write(msg); mp = f.name
    sig = sh_ok(["openssl", "pkeyutl", "-sign", "-inkey", sk, "-rawin", "-in", mp]); os.unlink(mp); return sig

def spki(raw, alg, PK):
    der = sh_ok(["openssl", "genpkey", "-algorithm", alg, "-outform", "DER"])
    pub = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"], input=der, capture_output=True).stdout
    return pub[:len(pub) - PK] + raw

def verify(raw_pk, alg, PK, msg, sig):
    der = spki(raw_pk, alg, PK)
    with tempfile.NamedTemporaryFile(delete=False) as fk: fk.write(der); kp = fk.name
    with tempfile.NamedTemporaryFile(delete=False) as fm: fm.write(msg); mp = fm.name
    with tempfile.NamedTemporaryFile(delete=False) as fs: fs.write(sig); sp = fs.name
    r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", kp, "-keyform", "DER", "-rawin", "-in", mp, "-sigfile", sp], capture_output=True)
    for x in (kp, mp, sp): os.unlink(x)
    return r.returncode == 0

def rec(scheme, name, pk, msg, sig, valid):
    return dict(scheme=scheme, name=name, expected=("valid" if valid else "reject"),
                public_key=pk.hex(), message=msg.hex(), signature=sig.hex())

out = []

p = ML44; genkey(f"{WORK}/ml.pem", p["alg"]); genkey(f"{WORK}/ml2.pem", p["alg"])
pk = rawpub(f"{WORK}/ml.pem", p["PK"]); pk2 = rawpub(f"{WORK}/ml2.pem", p["PK"])
msg = b"quantova-inc bip-360 ML-DSA-44 interop baseline"
sig = sign(f"{WORK}/ml.pem", msg)
assert len(sig) == p["SIG"] and verify(pk, p["alg"], p["PK"], msg, sig)
sig_e = sign(f"{WORK}/ml.pem", b""); assert verify(pk, p["alg"], p["PK"], b"", sig_e)
def mut(fn): s = bytearray(sig); fn(s); return bytes(s)
sig_ct = mut(lambda s: s.__setitem__(0, s[0] ^ 1))
sig_ho = mut(lambda s: s.__setitem__(p["SIG"] - 1, 0xFF))
cl = sig[p["SIG"] - 1]; hs = p["ctilde"] + p["zlen"]
def nc(s):
    idx = hs + (cl if cl < p["omega"] else p["omega"] - 1); s[idx] = 0xFF if s[idx] == 0 else s[idx] ^ 0x7F
sig_nc = mut(nc)
def mz(s): s[p["ctilde"]] = 0xFF; s[p["ctilde"] + 1] = 0xFF; s[p["ctilde"] + 2] = 0xFF
sig_z = mut(mz)
for t, s in [("ct", sig_ct), ("ho", sig_ho), ("nc", sig_nc), ("z", sig_z)]:
    assert not verify(pk, p["alg"], p["PK"], msg, s), t
assert not verify(pk2, p["alg"], p["PK"], msg, sig)
out += [
    rec("ML-DSA-44", "baseline valid signature", pk, msg, sig, True),
    rec("ML-DSA-44", "valid signature over empty message", pk, b"", sig_e, True),
    rec("ML-DSA-44", "bit flip in c_tilde", pk, msg, sig_ct, False),
    rec("ML-DSA-44", "valid signature under a different public key", pk2, msg, sig, False),
    rec("ML-DSA-44", "hint cumulative count above omega", pk, msg, sig_ho, False),
    rec("ML-DSA-44", "non canonical hint zero fill byte set", pk, msg, sig_nc, False),
    rec("ML-DSA-44", "z coefficient outside the gamma1 minus beta bound", pk, msg, sig_z, False),
]

p = SLH; genkey(f"{WORK}/slh.pem", p["alg"]); genkey(f"{WORK}/slh2.pem", p["alg"])
pk = rawpub(f"{WORK}/slh.pem", p["PK"]); pk2 = rawpub(f"{WORK}/slh2.pem", p["PK"])
msg = b"quantova-inc bip-360 SLH-DSA-SHA2-128s interop baseline"
sig = sign(f"{WORK}/slh.pem", msg)
assert len(sig) == p["SIG"] and verify(pk, p["alg"], p["PK"], msg, sig)
sig_e = sign(f"{WORK}/slh.pem", b""); assert verify(pk, p["alg"], p["PK"], b"", sig_e)
sig_fl = bytearray(sig); sig_fl[0] ^= 1; sig_fl = bytes(sig_fl)
assert not verify(pk, p["alg"], p["PK"], msg, sig_fl)
assert not verify(pk2, p["alg"], p["PK"], msg, sig)
out += [
    rec("SLH-DSA-SHA2-128s", "baseline valid signature", pk, msg, sig, True),
    rec("SLH-DSA-SHA2-128s", "valid signature over empty message", pk, b"", sig_e, True),
    rec("SLH-DSA-SHA2-128s", "bit flip in the signature", pk, msg, sig_fl, False),
    rec("SLH-DSA-SHA2-128s", "valid signature under a different public key", pk2, msg, sig, False),
    rec("SLH-DSA-SHA2-128s", "signature one byte short", pk, msg, sig[:-1], False),
    rec("SLH-DSA-SHA2-128s", "signature one byte long", pk, msg, sig + b"\x00", False),
]

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")
json.dump(out, open(path, "w"), indent=2)
print("wrote", path, "cases", len(out))
for o in out: print(o["expected"][:6], o["scheme"], o["name"])
