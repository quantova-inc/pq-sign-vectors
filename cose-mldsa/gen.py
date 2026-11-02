import json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "work")
os.makedirs(WORK, exist_ok=True)

ALG = {"ML-DSA-44": -48, "ML-DSA-65": -49, "ML-DSA-87": -50}
RAWLEN = {"ML-DSA-44": 1312, "ML-DSA-65": 1952, "ML-DSA-87": 2592}


def ce_uint(mt, n):
    b = mt << 5
    if n < 24:
        return bytes([b | n])
    if n < 256:
        return bytes([b | 24, n])
    if n < 65536:
        return bytes([b | 25, n >> 8, n & 255])
    raise ValueError(n)


def ce_int(n):
    if n >= 0:
        return ce_uint(0, n)
    return ce_uint(1, -1 - n)


def ce_bstr(b):
    return ce_uint(2, len(b)) + b


def ce_tstr(s):
    e = s.encode()
    return ce_uint(3, len(e)) + e


def ce_arr(items):
    return ce_uint(4, len(items)) + b"".join(items)


def ce_map(pairs):
    out = ce_uint(5, len(pairs))
    for k, v in pairs:
        out += k + v
    return out


def sh(args, inp=None):
    r = subprocess.run(args, input=inp, capture_output=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode(errors="replace"))
        raise SystemExit("fail " + " ".join(args))
    return r.stdout


def genkey(p, alg):
    sh(["openssl", "genpkey", "-algorithm", alg, "-out", p])


def rawpub(sk, rl):
    der = sh(["openssl", "pkey", "-in", sk, "-pubout", "-outform", "DER"])
    return der[len(der) - rl:]


def sign(sk, msg):
    t = tempfile.NamedTemporaryFile(delete=False); t.write(msg); t.close()
    s = sh(["openssl", "pkeyutl", "-sign", "-inkey", sk, "-rawin", "-in", t.name])
    os.unlink(t.name)
    return s


def spki(raw, alg, rl):
    der = sh(["openssl", "genpkey", "-algorithm", alg, "-outform", "DER"])
    pub = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                         input=der, capture_output=True).stdout
    return pub[:len(pub) - rl] + raw


def verify(raw, alg, rl, msg, sig):
    der = spki(raw, alg, rl)
    f = []
    for b in (der, msg, sig):
        t = tempfile.NamedTemporaryFile(delete=False); t.write(b); t.close(); f.append(t.name)
    r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", f[0],
                        "-keyform", "DER", "-rawin", "-in", f[1], "-sigfile", f[2]],
                       capture_output=True)
    for x in f:
        os.unlink(x)
    return r.returncode == 0


def sig_structure(protected_bstr_bytes, payload):
    # ["Signature1", protected, external_aad(empty), payload]
    return ce_arr([ce_tstr("Signature1"), ce_bstr(protected_bstr_bytes),
                   ce_bstr(b""), ce_bstr(payload)])


def cose_sign1(protected_bstr_bytes, payload, sig):
    body = ce_arr([ce_bstr(protected_bstr_bytes), ce_map([]), ce_bstr(payload), ce_bstr(sig)])
    return ce_uint(6, 18) + body  # tag 18


def rec(scheme, name, expected, raw, cose):
    return dict(scheme=scheme, cose_alg=ALG[scheme], name=name, expected=expected,
                public_key=raw.hex(), cose_sign1=cose.hex())


out = []
payload = b"quantova pq cose"
for scheme, alg in ALG.items():
    rl = RAWLEN[scheme]
    sk, sk2 = f"{WORK}/{scheme}.pem", f"{WORK}/{scheme}.2.pem"
    genkey(sk, scheme); genkey(sk2, scheme)
    pk, pk2 = rawpub(sk, rl), rawpub(sk2, rl)
    protected = ce_map([(ce_int(1), ce_int(alg))])  # {1: alg}
    ss = sig_structure(protected, payload)
    sig = sign(sk, ss)
    assert verify(pk, scheme, rl, ss, sig), f"{scheme} baseline"
    cose = cose_sign1(protected, payload, sig)
    out.append(rec(scheme, "baseline valid COSE_Sign1", "valid", pk, cose))

    # reject 1 flip a signature byte
    sb = bytearray(sig); sb[len(sb) // 2] ^= 1; sb = bytes(sb)
    assert not verify(pk, scheme, rl, ss, sb), f"{scheme} flip"
    out.append(rec(scheme, "a flipped signature byte", "reject", pk,
                   cose_sign1(protected, payload, sb)))

    # reject 2 wrong key
    assert not verify(pk2, scheme, rl, ss, sig), f"{scheme} wrong key"
    out.append(rec(scheme, "a genuine signature under a different key", "reject", pk2, cose))

    # reject 3 tampered payload, rebuilt Sig_structure differs
    payload2 = b"quantova pq cos3"
    ss_bad = sig_structure(protected, payload2)
    assert not verify(pk, scheme, rl, ss_bad, sig), f"{scheme} payload"
    out.append(rec(scheme, "a tampered payload", "reject", pk,
                   cose_sign1(protected, payload2, sig)))

    # reject 4 wrong alg in protected header, binding broken
    wrong_alg = -7  # ES256, a classical id
    protected_bad = ce_map([(ce_int(1), ce_int(wrong_alg))])
    ss_alg = sig_structure(protected_bad, payload)
    assert not verify(pk, scheme, rl, ss_alg, sig), f"{scheme} alg"
    out.append(rec(scheme, "a changed algorithm in the protected header", "reject", pk,
                   cose_sign1(protected_bad, payload, sig)))

    # reject 5 truncated signature
    assert not verify(pk, scheme, rl, ss, sig[:-1]), f"{scheme} trunc"
    out.append(rec(scheme, "a signature one byte short", "reject", pk,
                   cose_sign1(protected, payload, sig[:-1])))

p = os.path.join(HERE, "vectors.json")
json.dump(out, open(p, "w"), indent=2)
import collections
c = collections.Counter(o["expected"] for o in out)
print("wrote", p, "cases", len(out), "accept", c["valid"], "reject", c["reject"])
