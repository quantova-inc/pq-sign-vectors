# COSE ML-DSA signature vectors

An interop corpus for a COSE_Sign1 signature made with ML-DSA from FIPS 204. It covers the three parameter sets at the COSE algorithm identifiers the registry assigns, ML-DSA-44 at minus 48, ML-DSA-65 at minus 49 and ML-DSA-87 at minus 50. The same COSE profile is the one C2PA 2.5 adopts for a claim signature and the one a WebAuthn relying party would use to verify a post quantum assertion, so a verifier that agrees with this set agrees across both worlds.

Every signature is produced and checked with a stock OpenSSL 4.1.0 that offers native ML-DSA, using the pure mode from FIPS 204. The corpus shares no code with any other implementation, so a verifier that agrees with it has agreed across two independent implementations.

## Structure

Each record holds the scheme, the COSE algorithm identifier, a name, the expected result, the raw public key and the full COSE_Sign1 as hex. The signed input is the COSE Sig_structure, the array of the context string Signature1, the protected header, an empty external aad and the payload.

## Cases

Each parameter set carries a baseline valid COSE_Sign1 and five rejects. The rejects are a flipped signature byte, a genuine signature under a different key, a tampered payload, a changed algorithm in the protected header and a signature one byte short. The changed algorithm case shows that the protected header binds the algorithm into the signature, so a downgrade to a classical identifier fails. That is 18 cases in total, 3 accept and 15 reject.

## Run it

```
python3 verify.py
```

`verify.py` reads `vectors.json`, parses each COSE_Sign1, rebuilds the Sig_structure, verifies every case with OpenSSL and checks the result against the expected value. It reports `passed 18 failed 0` and exits nonzero on any mismatch. `gen.py` rebuilds the corpus from fresh keys and confirms every case before it writes the file.
