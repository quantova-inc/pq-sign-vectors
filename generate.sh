#!/usr/bin/env bash
# Copyright 2026
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Generate FIPS 204 ML-DSA conformance vectors over three canonical artifacts,
# a CycloneDX CBOM, an in-toto statement carried in a DSSE pre authentication
# encoding, and a model manifest. For each parameter set and each artifact a
# key, a genuine signature, and a tampered copy are written under vectors/.
# Reproduce with any OpenSSL that offers ML-DSA.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf vectors && mkdir -p vectors
SETS="44 65 87"

canon () { python3 -c "import json,sys;print(json.dumps(json.load(open(sys.argv[1])),sort_keys=True,separators=(',',':')),end='')" "$1"; }

# source artifacts (pretty form, the canonical form is derived)
mkdir -p src
cat > src/cbom.json <<'J'
{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:1b53623d-b96b-4660-8d25-f84b7f617c54","metadata":{"timestamp":"2026-10-31T00:00:00Z"},"components":[{"type":"cryptographic-asset","name":"RSA-2048","bom-ref":"alg-rsa-2048","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"signature","parameterSetIdentifier":"2048","nistQuantumSecurityLevel":0}}}]}
J
cat > src/intoto.json <<'J'
{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"model.bin","digest":{"sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildType":"demo","builder":{"id":"demo"}}}
J
cat > src/model.json <<'J'
{"format":"model-manifest/1","model":"demo-llm-7b","revision":"2026-10-01","weightsDigest":{"alg":"sha3-256","value":"aa9f1b7c3e2d4a5b6c7d8e9f00112233445566778899aabbccddeeff0011"},"producer":"demo"}
J

for a in cbom intoto model; do
  canon "src/$a.json" > "vectors/$a.canonical.json"
done
# DSSE pre authentication encoding over the in-toto statement
python3 - <<'PY'
body=open("vectors/intoto.canonical.json","rb").read()
pt=b"application/vnd.in-toto+json"
pae=b"DSSEv1 "+str(len(pt)).encode()+b" "+pt+b" "+str(len(body)).encode()+b" "+body
open("vectors/intoto.pae.bin","wb").write(pae)
PY

MANIFEST="vectors/MANIFEST.tsv"
printf "set\tartifact\tsigned_input\talgorithm_oid\tsig_bytes\n" > "$MANIFEST"
oid_for () { case "$1" in 44) echo 2.16.840.1.101.3.4.3.17;; 65) echo 2.16.840.1.101.3.4.3.18;; 87) echo 2.16.840.1.101.3.4.3.19;; esac; }

for s in $SETS; do
  openssl genpkey -algorithm "ML-DSA-$s" -out "vectors/mldsa$s.priv.pem" >/dev/null 2>&1
  openssl pkey -in "vectors/mldsa$s.priv.pem" -pubout -out "vectors/mldsa$s.pub.pem" >/dev/null 2>&1
  for a in cbom intoto model; do
    if [ "$a" = "intoto" ]; then IN="vectors/intoto.pae.bin"; else IN="vectors/$a.canonical.json"; fi
    SIG="vectors/$a.mldsa$s.sig"
    openssl pkeyutl -sign -inkey "vectors/mldsa$s.priv.pem" -rawin -in "$IN" -out "$SIG" >/dev/null 2>&1
    printf "%s\t%s\t%s\t%s\t%s\n" "$s" "$a" "$(basename "$IN")" "$(oid_for "$s")" "$(wc -c < "$SIG" | tr -d ' ')" >> "$MANIFEST"
  done
done

# one tampered copy per artifact, the canonical form with a single byte changed
for a in cbom model; do
  python3 -c "b=bytearray(open('vectors/$a.canonical.json','rb').read()); b[-2]=b[-2]^1; open('vectors/$a.tampered.json','wb').write(b)"
done
python3 -c "b=bytearray(open('vectors/intoto.pae.bin','rb').read()); b[-1]=b[-1]^1; open('vectors/intoto.pae.tampered.bin','wb').write(b)"

echo "generated $(($(wc -l < "$MANIFEST")-1)) genuine vectors across sets $SETS"
column -t -s$'\t' "$MANIFEST"
