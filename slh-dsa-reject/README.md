# SLH-DSA reject and boundary vectors

A reject and boundary corpus for SLH-DSA from FIPS 205, covering all twelve parameter sets across the SHA2 and SHAKE families at the 128, 192 and 256 levels in both the small and fast variants. It fills the half of interop that the positive known answer tests do not reach, the signatures a verifier is required to refuse. Across the signature libraries that now ship SLH-DSA the positive and known answer coverage is strong while a curated reject corpus is usually missing, so this set targets that gap.

Every signature is produced and checked with a stock OpenSSL 4.1.0 that offers native SLH-DSA, using the empty context and the pure mode from FIPS 205. The corpus shares no code with any other implementation, so a verifier that agrees with it has agreed across two independent implementations, and the reject cases are the ones that catch decode, length and routing mistakes.

## Parameter sets

SLH-DSA-SHA2-128s, SLH-DSA-SHA2-128f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-256s, SLH-DSA-SHA2-256f and the matching six SLH-DSA-SHAKE sets.

## Cases per parameter set

Each parameter set carries a baseline valid signature, a bit flip in the first signature byte, a bit flip in the middle of the signature, a genuine signature verified against the wrong public key, a signature one byte short and a signature one byte long. On top of that, for each level and variant where the SHA2 and SHAKE sets share the same key and signature sizes, there is a cross family case where a SHA2 signature is verified under the same size SHAKE key and must be refused. That is 78 cases in total, 12 accept and 66 reject.

Each record holds the scheme, a name, the expected result and the public key, message and signature as hex.

## Run it

```
python3 verify.py
```

`verify.py` reads `vectors.json`, wraps each raw public key for its scheme, verifies every case with OpenSSL and checks the result against the expected value. It reports `passed 78 failed 0` and exits nonzero on any mismatch. `gen.py` rebuilds the corpus from fresh keys and confirms every case before it writes the file.
