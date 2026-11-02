import json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "work")
os.makedirs(WORK, exist_ok=True)

SUITE = {"ML-DSA-44": "MlDsa44", "ML-DSA-65": "MlDsa65", "ML-DSA-87": "MlDsa87"}
RAWLEN = {"ML-DSA-44": 1312, "ML-DSA-65": 1952, "ML-DSA-87": 2592}


def sh(args, inp=None):
    r = subprocess.run(args, input=inp, capture_output=True)
    if r.returncode != 0 and args[1] not in ("pkeyutl",):
        sys.stderr.write(r.stderr.decode(errors="replace")); raise SystemExit("fail " + " ".join(args))
    return r


def genkey(p, alg):
    sh(["openssl", "genpkey", "-algorithm", alg, "-out", p])


def rawpub(sk, rl):
    der = sh(["openssl", "pkey", "-in", sk, "-pubout", "-outform", "DER"]).stdout
    return der[len(der) - rl:]


def ctx_opt(ctx):
    return ["-pkeyopt", "context-string:" + ctx] if ctx else []


def sign(sk, msg, ctx):
    t = tempfile.NamedTemporaryFile(delete=False); t.write(msg); t.close()
    r = sh(["openssl", "pkeyutl", "-sign", "-inkey", sk, "-rawin", "-in", t.name] + ctx_opt(ctx))
    os.unlink(t.name)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode()); raise SystemExit("sign fail")
    return r.stdout


def spki(raw, alg, rl):
    der = sh(["openssl", "genpkey", "-algorithm", alg, "-outform", "DER"]).stdout
    pub = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                         input=der, capture_output=True).stdout
    return pub[:len(pub) - rl] + raw


def verify(raw, alg, rl, msg, sig, ctx):
    der = spki(raw, alg, rl)
    f = []
    for b in (der, msg, sig):
        t = tempfile.NamedTemporaryFile(delete=False); t.write(b); t.close(); f.append(t.name)
    r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", f[0], "-keyform", "DER",
                        "-rawin", "-in", f[1], "-sigfile", f[2]] + ctx_opt(ctx), capture_output=True)
    for x in f:
        os.unlink(x)
    return r.returncode == 0


def rec(alg, name, expected, raw, ctx, msg, sig):
    return dict(scheme=alg, suite=SUITE[alg], name=name, expected=expected,
                context=ctx.encode().hex(), public_key=raw.hex(),
                message=msg.hex(), signature=sig.hex())


out = []
msg = b"iroha soranet pq ml dsa interop"
for alg, rl in RAWLEN.items():
    sk, sk2 = f"{WORK}/{alg}.pem", f"{WORK}/{alg}.2.pem"
    genkey(sk, alg); genkey(sk2, alg)
    pk, pk2 = rawpub(sk, rl), rawpub(sk2, rl)

    sig_empty = sign(sk, msg, "")
    assert verify(pk, alg, rl, msg, sig_empty, ""), f"{alg} empty ctx"
    out.append(rec(alg, "accept with an empty context", "valid", pk, "", msg, sig_empty))

    sig_ctx = sign(sk, msg, "iroha")
    assert verify(pk, alg, rl, msg, sig_ctx, "iroha"), f"{alg} ctx iroha"
    out.append(rec(alg, "accept with the context iroha", "valid", pk, "iroha", msg, sig_ctx))

    # context binding, signature made under empty context must fail under context iroha
    assert not verify(pk, alg, rl, msg, sig_empty, "iroha"), f"{alg} ctx bind"
    out.append(rec(alg, "reject on a context mismatch, signed with an empty context verified under iroha",
                   "reject", pk, "iroha", msg, sig_empty))

    sb = bytearray(sig_empty); sb[len(sb) // 2] ^= 1; sb = bytes(sb)
    assert not verify(pk, alg, rl, msg, sb, ""), f"{alg} flip"
    out.append(rec(alg, "reject on a flipped signature byte", "reject", pk, "", msg, sb))

    assert not verify(pk2, alg, rl, msg, sig_empty, ""), f"{alg} wrong key"
    out.append(rec(alg, "reject under a different public key", "reject", pk2, "", msg, sig_empty))

    assert not verify(pk, alg, rl, msg, sig_empty[:-1], ""), f"{alg} trunc"
    out.append(rec(alg, "reject on a signature one byte short", "reject", pk, "", msg, sig_empty[:-1]))

p = os.path.join(HERE, "vectors.json")
json.dump(out, open(p, "w"), indent=2)
import collections
c = collections.Counter(o["expected"] for o in out)
print("wrote", p, "cases", len(out), "accept", c["valid"], "reject", c["reject"])
