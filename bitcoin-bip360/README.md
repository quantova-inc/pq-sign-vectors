# Interop and reject vectors for the BIP-360 PQ schemes

A reproducible accept and reject corpus for the two post quantum schemes that libbitcoinpqc implements, ML-DSA-44 from FIPS 204 and SLH-DSA-SHA2-128s from FIPS 205. The golden vectors in that library are auto generated from the library itself, so they lock the current output in place but they do not show that the output matches the standard under a second implementation and they carry no cases that a verifier is required to refuse. This set covers both of those.

Every signature here is produced and checked with a stock OpenSSL 4.1.0 that offers native ML-DSA and SLH-DSA, using the empty context and the pure mode from the FIPS standards. The corpus shares no code with libbitcoinpqc, so a signature that it accepts and this set accepts has agreed across two independent implementations and a malformed signature that both refuse has been refused across two independent implementations. The second property is the one that catches decode and bounds mistakes.

## Schemes and sizes

| Scheme | Public key | Signature |
|---|---|---|
| ML-DSA-44 | 1312 | 2420 |
| SLH-DSA-SHA2-128s | 32 | 7856 |

## Cases

ML-DSA-44 carries a baseline valid signature, a valid signature over an empty message, a bit flip in c tilde, a genuine signature verified against the wrong key, a hint cumulative count driven above omega, a non canonical hint with a nonzero byte in the zero fill region and a response coefficient pushed past the gamma1 minus beta bound. SLH-DSA-SHA2-128s carries a baseline valid signature, a valid signature over an empty message, a bit flip in the signature, a genuine signature verified against the wrong key, a signature one byte short and a signature one byte long.

Each record holds the scheme, a name, the expected result and the public key, message and signature as hex.

## Run it

```
python3 verify.py
```

`verify.py` reads `vectors.json`, wraps each raw public key for its scheme, verifies every case with OpenSSL and checks the result against the expected value. It reports `passed 13 failed 0` and exits nonzero on any mismatch. `gen.py` rebuilds the corpus from fresh keys and confirms every case before it writes the file.
