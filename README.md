# pq-sign-vectors

Conformance vectors for an ML-DSA signature from FIPS 204 over three canonical artifacts, a CycloneDX CBOM, an in-toto statement carried in a DSSE pre authentication encoding, and a model manifest. The vectors are the evidence behind three standards proposals, one to carry a post quantum signature over a CBOM, one to sign an in-toto attestation with ML-DSA, and one to sign content and model provenance with ML-DSA.

Everything here is produced with a stock OpenSSL that offers ML-DSA, so any reviewer can reproduce it and nothing depends on a particular implementation.

## What it shows

`generate.sh` writes, for each of ML-DSA-44, ML-DSA-65 and ML-DSA-87, a key pair, a genuine signature over each artifact, and a tampered copy of each artifact. `verify.sh` then checks every case and exits nonzero if any case is wrong.

The run proves three properties for each parameter set and each artifact.

- A genuine signature over the canonical input verifies.
- The same signature over a one byte change to the input fails.
- A signature made under one parameter set does not verify under another parameter set key.

The signature sizes match FIPS 204, 2420 bytes for ML-DSA-44, 3309 for ML-DSA-65 and 4627 for ML-DSA-87, and the algorithm identifiers are the NIST CSOR object identifiers 2.16.840.1.101.3.4.3.17, .18 and .19.

## Run it

```
bash generate.sh
bash verify.sh
```

A clean run reports twenty one checks passed and zero failed.

## Layout

- `src` the readable source of each artifact
- `vectors` the canonical inputs, the DSSE pre authentication encoding, the keys, the signatures, the tampered copies, and `MANIFEST.tsv`
- `generate.sh` builds the vectors
- `verify.sh` checks them

## License

Apache-2.0 OR MIT.

## Reject vectors

The `reject-vectors` directory carries a companion corpus for the other half of interop, the signatures a verifier must refuse, aimed at the hint and length and bounds checks rather than the arithmetic.

## COSE vectors

The `cose-mldsa` directory carries a COSE_Sign1 interop corpus for ML-DSA at the COSE algorithm identifiers minus 48, minus 49 and minus 50, the same profile C2PA 2.5 adopts and a WebAuthn relying party would verify.

## Context vectors

The `ml-dsa-context` directory carries an ML-DSA interop corpus signed with an explicit context string, matching a ledger that signs with a context such as the soranet_pq crate in Hyperledger Iroha, with a context binding reject case.
