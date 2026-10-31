#!/usr/bin/env bash
# Copyright 2026
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Check the reject corpus. The valid signature must verify and every reject
# vector must fail. Exits nonzero if any case is wrong.
set -uo pipefail
cd "$(dirname "$0")"
pass=0
fail=0
v () { openssl pkeyutl -verify -pubin -inkey pk.pem -rawin -in message.bin -sigfile "$1" >/dev/null 2>&1; }
if v valid.sig; then echo "verify  valid.sig"; pass=$((pass+1)); else echo "ERROR   valid.sig did not verify"; fail=$((fail+1)); fi
for r in reject_flip_ctilde reject_truncated reject_extended reject_hint_over_omega reject_hint_noncanonical reject_z_extreme; do
  if v "$r.sig"; then echo "ERROR   $r.sig verified but must be rejected"; fail=$((fail+1)); else echo "reject  $r.sig"; pass=$((pass+1)); fi
done
echo "passed $pass failed $fail"
[ "$fail" -eq 0 ]
