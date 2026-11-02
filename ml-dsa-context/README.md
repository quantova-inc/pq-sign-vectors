# ML-DSA context and interop vectors

An interop corpus for ML-DSA from FIPS 204 signed with an explicit context string across ML-DSA-44, ML-DSA-65 and ML-DSA-87. It matches the signing shape a ledger exposes when it signs with a context, for example the soranet_pq crate in Hyperledger Iroha whose verify path takes a suite, a context up to 255 bytes, a message and a detached signature.

Every signature is produced and checked with a stock OpenSSL 4.1.0 that offers native ML-DSA, using the pure mode from FIPS 204 with the context carried in the signed input. The corpus shares no code with any other implementation, so a verifier that agrees with it has agreed across two independent FIPS 204 implementations.

## Structure

Each record holds the scheme, a suite label that matches the Iroha naming, a name, the expected result, the context, the public key, the message and the signature, all as hex. An empty context is an empty hex string.

## Cases

Each parameter set carries two accepts and four rejects. The accepts are an empty context and the context iroha. The rejects are a context mismatch where a signature made with an empty context is verified under the context iroha, a flipped signature byte, a signature under a different public key and a signature one byte short. The context mismatch case shows that the context binds into the signature, so a signature made for one context does not carry to another. That is 18 cases in total, 6 accept and 12 reject.

## Run it

```
python3 verify.py
```

`verify.py` reads `vectors.json` and verifies every case with OpenSSL under the stated context, then checks the result against the expected value. It reports `passed 18 failed 0` and exits nonzero on any mismatch. `gen.py` rebuilds the corpus from fresh keys and confirms every case before it writes the file.
