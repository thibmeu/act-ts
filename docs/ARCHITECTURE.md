# Architecture

```
packages/
  sigma-proofs/   # draft-irtf-cfrg-sigma-protocols-03 + fiat-shamir-03
  act-ts/         # draft-schlesinger-mole-ec-act-00 (EC-ACT), P256-SHA256
```

`act-ts` depends on `sigma-proofs`; both use `@noble/curves` and `@noble/hashes` only.

## sigma-proofs

| File                 | Spec                         | Contents                                                                  |
| -------------------- | ---------------------------- | ------------------------------------------------------------------------- |
| `ciphersuites.ts`    | sigma §8                     | P-256 and BLS12-381 G1 suites; scalar and element codecs                  |
| `linear-relation.ts` | sigma §3, §4.2, §4.4         | `LinearRelation`: serialize/deserialize, `validate`, `commit`, `simulate` |
| `fiat-shamir.ts`     | sigma §5, fiat-shamir §3, §5 | `deriveSessionId`, compact and batchable prove/verify                     |

A relation is sparse: equations of image terms `(element, coeff)` and terms `(scalar, element, coeff)`, with the generator at element index 0. The XOF duplex sponge is used for one absorb-then-squeeze, which is SHAKE128 over `session_id || 0^136 || data`.

### Sync and async from one implementation

Prove and verify, and every ACT operation, are generators (`Effect<R>`) that yield batches of scalar multiplications (`Job`: point, scalar, secret?, equation group) and receive the products. `runSync` executes batches on noble; `runAsync` hands them to the suite's native backend, `mulManyWebCrypto` for P-256 (`webcrypto.ts`):

- ECDH `deriveBits(k, Q)` gives `x(k·Q)` natively. Importing `k` (PKCS#8) and exporting it as JWK yields `K = k·G`; with `x(k·(Q+G)) = x(k·Q + K)`, the addition formula gives `y` with one division (batched), no square root. A job on `G` is free.
- Cost per distinct scalar is one import (~120 µs, main thread); per distinct point two public imports (cached per point object, so generators are imported once). Derivations run off the main thread in Node.
- Public scalars `k` and `p − k` share one import. **Secret scalars are never shared or special-cased**: a secret `k` is computed as `(k+1)·Q − Q`, so zero (a hidden bit) takes the same path, and equal secrets are imported separately. `test/protocol.test.ts` checks that a spend's import count does not depend on the balance.
- Any failure (engine without the formats, identity results, a point off the curve) falls back to noble per job.

`runSync` merges jobs on the same point within an equation (one multiplication); the WebCrypto backend keeps them apart to share scalars such as the challenge across equations.

Other performance choices, all generic:

- `commit` merges terms per element, so each distinct base costs one constant-time multiplication. Optional prover _openings_ expand an element into a known representation, so the prover multiplies only fixed bases.
- `simulate` merges terms per element; a single-term image is emitted in the same equation group (see above).
- In `validate`, coefficient −1 is a negation, not a 256-bit multiplication.
- `serialize` normalizes all elements with one batched inversion and is cached.

## act-ts

| File       | Spec                         | Contents                                                        |
| ---------- | ---------------------------- | --------------------------------------------------------------- |
| `group.ts` | EC-IHAT §3.1, §4.2–4.4, §7.1 | HashToGroup/Scalar, DeriveScalars/Nonces, DeriveKeyPair, codecs |
| `act.ts`   | EC-ACT §4                    | Configuration, relations, issuance, spending, refunds           |
| `wire.ts`  | EC-ACT §4.7                  | Message, state, Credential, and key encodings                   |

The three relations (Commitment, Signature, Spend) are compiled with the element and scalar order of the draft's Relation blocks; that order is what `SerializeLinearRelation`, and so every proof, depends on. Generators H1–H4 carry noble fixed-base tables (window 8). Each operation batches all its multiplications in as few rounds as its data dependencies allow (`proveSpend`: fixed-base products, then the rerandomization, then the commitment). `B + ctx·H4` is cached per configuration and credential context; `K'` is computed as `K_n + Σ wⱼ·Com1[j]` (additions only); a bit times H1 is a branch-free select.

Randomness: every algorithm draws `random(48)` seeds and derives its scalars (`DeriveScalars`), its signing exponent and its prover nonces (`DeriveNonces` over the secret, the session, and the relation). Replaying the seeds reproduces every output, which the vector tests rely on.

## Tests

| Test                                | Source                                                     |
| ----------------------------------- | ---------------------------------------------------------- |
| `sigma-proofs/test/vectors.test.ts` | sigma-protocols-03 Appendix A, 75 vectors, re-proven       |
| `act-ts/test/vectors.test.ts`       | EC-ACT-00 Appendix A (L = 4) and act-rs vectors (L = 1–64) |
| `act-ts/test/protocol.test.ts`      | Flows, binding, amounts, single use, decoding              |
