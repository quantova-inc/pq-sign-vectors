# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

import json
import math
import os
import subprocess
import sys
import tempfile

WORK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "work")
os.makedirs(WORK, exist_ok=True)

SETS = {
    65: dict(alg="ML-DSA-65", PK=1952, SIG=3309, BASE=9000, ctilde=48, zlen=3200, omega=55),
    87: dict(alg="ML-DSA-87", PK=2592, SIG=4627, BASE=13500, ctilde=64, zlen=4480, omega=75),
}


def sh_ok(args):
    r = subprocess.run(args, capture_output=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode(errors="replace"))
        raise SystemExit("cmd failed " + " ".join(args))
    return r.stdout


def genkey(path, alg):
    sh_ok(["openssl", "genpkey", "-algorithm", alg, "-out", path])


def rawpub(sk, PK):
    der = sh_ok(["openssl", "pkey", "-in", sk, "-pubout", "-outform", "DER"])
    return der[len(der) - PK:], der


def sign(sk, msg):
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(msg)
        mp = f.name
    sig = sh_ok(["openssl", "pkeyutl", "-sign", "-inkey", sk, "-rawin", "-in", mp])
    os.unlink(mp)
    return sig


def verify(spki_der, msg, sig):
    with tempfile.NamedTemporaryFile(delete=False) as fk:
        fk.write(spki_der)
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
    for p in (kp, mp, sp):
        os.unlink(p)
    return r.returncode == 0


def gas(base, L, PK, SIG):
    return base + 6 * math.ceil(max(0, L - PK - SIG) / 32)


def word(valid):
    return "00" * 31 + ("01" if valid else "00")


def vec(name, raw_input, valid, base, PK, SIG, nobench=False):
    return dict(Input=raw_input.hex(), Expected=word(valid),
                Gas=gas(base, len(raw_input), PK, SIG), Name=name, NoBenchmark=nobench)


def build():
    out = []
    for bits, p in SETS.items():
        PK, SIG, BASE = p["PK"], p["SIG"], p["BASE"]
        sk = os.path.join(WORK, f"sk{bits}.pem")
        sk2 = os.path.join(WORK, f"sk{bits}_other.pem")
        genkey(sk, p["alg"])
        genkey(sk2, p["alg"])
        pk, der = rawpub(sk, PK)
        pk2, der2 = rawpub(sk2, PK)

        msg = f"quantova-inc eip-8355 {p['alg']} interop baseline".encode()
        sig = sign(sk, msg)
        if len(sig) != SIG or not verify(der, msg, sig):
            raise SystemExit("baseline failed")
        sig_e = sign(sk, b"")
        if not verify(der, b"", sig_e):
            raise SystemExit("empty message baseline failed")

        def mutate(fn):
            s = bytearray(sig)
            fn(s)
            return bytes(s)

        sig_ct = mutate(lambda s: s.__setitem__(0, s[0] ^ 0x01))
        sig_ho = mutate(lambda s: s.__setitem__(SIG - 1, 0xFF))
        counts_last = sig[SIG - 1]
        hint_pos_start = p["ctilde"] + p["zlen"]

        def m_nc(s):
            w = counts_last
            idx = hint_pos_start + (w if w < p["omega"] else p["omega"] - 1)
            s[idx] = 0xFF if s[idx] == 0 else (s[idx] ^ 0x7F)

        sig_nc = mutate(m_nc)
        zoff = p["ctilde"]

        def m_z(s):
            s[zoff] = 0xFF
            s[zoff + 1] = 0xFF
            s[zoff + 2] = 0xFF

        sig_z = mutate(m_z)

        for tag, s in [("ctilde", sig_ct), ("over_omega", sig_ho),
                       ("noncanonical", sig_nc), ("zbound", sig_z)]:
            if verify(der, msg, s):
                raise SystemExit(f"{bits} {tag} verified")
        if verify(der2, msg, sig):
            raise SystemExit(f"{bits} wrong key verified")

        base_in = pk + sig + msg
        out += [
            vec(f"ML-DSA-{bits} baseline valid signature", pk + sig + msg, True, BASE, PK, SIG),
            vec(f"ML-DSA-{bits} valid signature over empty message, input length exactly PK_LEN + SIG_LEN", pk + sig_e, True, BASE, PK, SIG),
            vec(f"ML-DSA-{bits} bit flip in c_tilde, well formed but does not verify", pk + sig_ct + msg, False, BASE, PK, SIG),
            vec(f"ML-DSA-{bits} valid signature under a different public key", pk2 + sig + msg, False, BASE, PK, SIG),
            vec(f"ML-DSA-{bits} hint cumulative count above omega, non decodable hint", pk + sig_ho + msg, False, BASE, PK, SIG),
            vec(f"ML-DSA-{bits} non canonical hint, nonzero byte in the zero fill region", pk + sig_nc + msg, False, BASE, PK, SIG),
            vec(f"ML-DSA-{bits} z coefficient outside the gamma1 minus beta bound", pk + sig_z + msg, False, BASE, PK, SIG),
            vec(f"ML-DSA-{bits} input one byte shorter than PK_LEN + SIG_LEN", base_in[:PK + SIG - 1], False, BASE, PK, SIG, nobench=True),
        ]
    return out


def main():
    out = build()
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-vectors.generated.json")
    json.dump(out, open(path, "w"), indent=2)
    print("wrote", path, "cases", len(out))


if __name__ == "__main__":
    main()
