# ML-DSA verification vectors for EIP-8355

A reproducible accept and reject corpus for the three ML-DSA verification precompiles in EIP-8355, aimed at the coverage the merged fixture does not reach. The checked in `assets/eip-8355/test-vectors.json` carries three cases for ML-DSA-44 only, one valid, one bit flip in c tilde, and one short input. This set adds ML-DSA-65 and ML-DSA-87, and it exercises the malformed encodings that the EIP requires a verifier to refuse.

Section "Verification" of the EIP states that on a malformed encoding, including out of range coefficients, a non canonical hint h, and a norm bound failure on z, the precompile must return failure rather than accept. None of those cases has a vector today. Each one is covered here for both of the higher parameter sets.

## Input and output

Each precompile takes `pubkey ++ signature ++ message` with no length fields. The public key and signature have fixed lengths from the parameter set and the message is the trailing bytes. The precompile returns a 32 byte word, `0x00..01` for a valid signature and `0x00..00` for anything else. Gas is `BASE + 6 * ceil(max(0, L - PK_LEN - SIG_LEN) / 32)`.

| Parameter set | PK_LEN | SIG_LEN | Base gas |
|---|---|---|---|
| ML-DSA-65 | 1952 | 3309 | 9000 |
| ML-DSA-87 | 2592 | 4627 | 13500 |

## Cases, per parameter set

| Name | Expected | What it exercises |
|---|---|---|
| baseline valid signature | valid | a genuine signature over a non empty message |
| valid signature over empty message | valid | input length exactly PK_LEN + SIG_LEN, the empty message boundary FIPS 204 admits |
| bit flip in c tilde | reject | a well formed signature whose recomputed challenge no longer matches |
| valid signature under a different public key | reject | a genuine signature verified against the wrong key |
| hint cumulative count above omega | reject | the final hint count raised past omega so hint unpacking refuses it |
| non canonical hint | reject | a nonzero byte in the zero fill region of the hint |
| z coefficient outside the gamma1 minus beta bound | reject | a response coefficient driven past the norm bound |
| input one byte shorter than PK_LEN + SIG_LEN | reject | the length rule, failure without reverting |

## How these were produced

Every signature is produced and checked with a stock OpenSSL 4.1.0 that offers native ML-DSA, using the empty context and the pure mode that EIP-8355 specifies. The corpus shares no code with any Ethereum client, so a client that agrees with it agrees across two independent implementations. One of the ML-DSA-65 accept cases is taken directly from the NIST ACVP FIPS 204 verify set and reproduces the expected accept under OpenSSL, so the set is tied to the public conformance vectors as well as to an independent verifier. The generator confirms at build time that each valid case verifies and each reject case fails before it writes the file.

## Run it

```
python3 verify.py
```

`verify.py` reads `test-vectors.json`, splits each input by the parameter set lengths, verifies it with OpenSSL, and checks the result against the expected word. It reports `passed 16 failed 0` and exits nonzero on any mismatch. `gen.py` rebuilds the corpus from fresh keys.

## Measured verification cost

On OpenSSL 4.1.0 a single verification is about 40 microseconds for ML-DSA-44, about 63 for ML-DSA-65, and about 101 for ML-DSA-87. The work ladder across the three sets is steeper than the base gas ladder, so the ML-DSA-87 base looks low relative to ML-DSA-44 if gas is meant to track verification time, which is worth checking against a client side benchmark before the numbers are fixed.
