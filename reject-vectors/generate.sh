#!/usr/bin/env bash
# Copyright 2026
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Build the ML-DSA-65 reject corpus. One genuine signature that must verify and
# six crafted signatures that a compliant verifier is required to refuse. The
# crafted cases target the decode and bounds checks rather than the arithmetic.
set -euo pipefail
cd "$(dirname "$0")"
ALG=ML-DSA-65
printf 'pq-sign-vectors ML-DSA-65 reject corpus message' > message.bin
openssl genpkey -algorithm "$ALG" -out sk.pem
openssl pkey -in sk.pem -pubout -out pk.pem
openssl pkey -in pk.pem -pubin -outform DER -out pk.der
openssl pkeyutl -sign -inkey sk.pem -rawin -in message.bin -out valid.sig
python3 - <<'PY'
TOTAL=3309
ZEND=3248
OMEGA=55
sig=bytearray(open('valid.sig','rb').read())
assert len(sig)==TOTAL, len(sig)
total_hints=sig[TOTAL-1]
fill=ZEND+total_hints if total_hints < OMEGA else TOTAL-2
def w(n,b): open(n,'wb').write(bytes(b))
a=bytearray(sig); a[0]^=0x01;                      w('reject_flip_ctilde.sig',a)
w('reject_truncated.sig', sig[:-1])
w('reject_extended.sig', sig+bytes([0x00]))
a=bytearray(sig); a[TOTAL-1]=0xFF;                 w('reject_hint_over_omega.sig',a)
a=bytearray(sig); a[fill]=0xFF;                    w('reject_hint_noncanonical.sig',a)
a=bytearray(sig); a[ZEND-1]=0xFF; a[ZEND-2]=0xFF;  w('reject_z_extreme.sig',a)
PY
rm -f sk.pem
