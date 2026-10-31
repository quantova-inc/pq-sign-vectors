#!/usr/bin/env bash
# Copyright 2026
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Verify every vector produced by generate.sh. A genuine signature over its
# canonical input must verify, and the same signature over a tampered copy must
# fail. Exits nonzero if any genuine vector fails or any tampered vector passes.
set -uo pipefail
cd "$(dirname "$0")"
SETS="44 65 87"
pass=0
fail=0

check () { # description expected(ok|bad) pub input sig
  local desc="$1" expect="$2" pub="$3" in="$4" sig="$5"
  if openssl pkeyutl -verify -pubin -inkey "$pub" -rawin -in "$in" -sigfile "$sig" >/dev/null 2>&1; then
    got=ok; else got=bad; fi
  if [ "$got" = "$expect" ]; then echo "PASS  $desc  ($got as expected)"; pass=$((pass+1));
  else echo "FAIL  $desc  (got $got, wanted $expect)"; fail=$((fail+1)); fi
}

for s in $SETS; do
  pub="vectors/mldsa$s.pub.pem"
  # genuine must verify
  check "ML-DSA-$s cbom genuine"   ok  "$pub" "vectors/cbom.canonical.json"  "vectors/cbom.mldsa$s.sig"
  check "ML-DSA-$s intoto genuine" ok  "$pub" "vectors/intoto.pae.bin"       "vectors/intoto.mldsa$s.sig"
  check "ML-DSA-$s model genuine"  ok  "$pub" "vectors/model.canonical.json" "vectors/model.mldsa$s.sig"
  # tampered must fail
  check "ML-DSA-$s cbom tampered"   bad "$pub" "vectors/cbom.tampered.json"      "vectors/cbom.mldsa$s.sig"
  check "ML-DSA-$s intoto tampered" bad "$pub" "vectors/intoto.pae.tampered.bin" "vectors/intoto.mldsa$s.sig"
  check "ML-DSA-$s model tampered"  bad "$pub" "vectors/model.tampered.json"     "vectors/model.mldsa$s.sig"
  # a signature from one parameter set must not verify under another key
  other=$([ "$s" = "44" ] && echo 65 || echo 44)
  check "ML-DSA-$s cbom under set $other key" bad "vectors/mldsa$other.pub.pem" "vectors/cbom.canonical.json" "vectors/cbom.mldsa$s.sig"
done

echo "----"
echo "passed $pass  failed $fail"
[ "$fail" -eq 0 ]
