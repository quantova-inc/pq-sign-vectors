# ML-DSA reject vectors

A small reject and boundary corpus for ML-DSA from FIPS 204. It covers the half of interop that positive known answer tests do not reach, the signatures a verifier is required to refuse. Two correct implementations should accept the same valid signature, and they should also refuse the same malformed one, and it is the second property that catches the routing and buffer mistakes that only appear on inputs the code is meant to turn away.

Everything here is produced with a stock OpenSSL that offers ML-DSA, so it shares no code with any other implementation and any reviewer can reproduce it.

## What it shows

The parameter set is ML-DSA-65. The signed message is in `message.bin` and the public key is in `pk.pem` and `pk.der`. One genuine signature is the anchor and six crafted signatures must each be rejected. The crafted cases aim at the decode and bounds checks that a wrapper is responsible for rather than at the arithmetic.

| file | expected | what is altered | reason a compliant verifier refuses it |
|---|---|---|---|
| `valid.sig` | verifies | nothing | the baseline signature over `message.bin` |
| `reject_flip_ctilde.sig` | rejected | one bit flipped in the commitment hash c tilde | the recomputed challenge no longer matches |
| `reject_truncated.sig` | rejected | one byte removed, length 3308 | wrong signature length at the API boundary |
| `reject_extended.sig` | rejected | one trailing byte added, length 3310 | wrong signature length at the API boundary |
| `reject_hint_over_omega.sig` | rejected | the final cumulative hint count raised to 255 | hint unpacking refuses a count above omega |
| `reject_hint_noncanonical.sig` | rejected | a fill position in the hint set to a nonzero value | hint unpacking refuses a nonzero fill byte |
| `reject_z_extreme.sig` | rejected | the final response coefficient driven to an extreme value | the response fails the gamma1 minus beta norm bound |

## Layout of an ML-DSA-65 signature

The 3309 byte signature is the commitment hash c tilde in the first 48 bytes, the response z in the next 3200 bytes, and the hint h in the last 61 bytes. The hint is 55 position bytes followed by 6 cumulative count bytes. omega is 55 and k is 6. The hint and the length cases are the ones that tend to expose integration bugs, since a verifier that skips the canonical hint check or the length check will accept a signature it should refuse.

## Run it

```
bash generate.sh
bash verify.sh
```

`generate.sh` writes a key pair, a genuine signature and the six crafted signatures. `verify.sh` then confirms the genuine one verifies and every crafted one fails, and exits nonzero if any case is wrong. The private key is removed at the end of generation and is not kept.
