# ACT Draft Migration: Current vs sigma-draft-compliance

This document details the changes needed to migrate from the current draft implementation to the new `samschles/sigma-draft-compliance` branch.

## Summary of Changes

| Area                   | Current Implementation          | New Draft                                              |
| ---------------------- | ------------------------------- | ------------------------------------------------------ |
| **Fiat-Shamir**        | BLAKE3-based custom transcript  | `NISigmaProtocol` from draft-irtf-cfrg-fiat-shamir     |
| **Proof construction** | Manual sigma protocol           | `LinearRelation` + `NISigmaProtocol` from sigma-proofs |
| **Range proof**        | CDS OR-proofs (2L simulations)  | Algebraic binary constraint (2 equations per bit)      |
| **Wire format**        | CBOR maps                       | TLS presentation language                              |
| **Hash function**      | BLAKE3 (64-byte XOF)            | SHAKE128                                               |
| **Test vectors**       | Partial (truncated spend_proof) | TODO in new draft                                      |

## Detailed Changes

### 1. Fiat-Shamir Transform

**Current (`transcript.ts`):**

- Custom BLAKE3-based transcript
- Length-prefixed messages with 8-byte big-endian length
- Protocol version string included
- System parameters (H1-H4) included in transcript

**New Draft:**

- Uses `NISigmaProtocol` interface from draft-irtf-cfrg-fiat-shamir
- Session identifier: `domain_separator + "<operation>"` + encoded values
- Codec: `Ristretto255Codec` extending `ByteSchnorrCodec`
- Hash: SHAKE128 (not BLAKE3)

**Migration:**

- Replace `Transcript` class with `NISigmaProtocol` from sigma-proofs package
- Session IDs change from labels to structured format:
  - `"request"` → `domain_separator + "request"`
  - `"respond"` → `domain_separator + "respond" + Encode(c) + Encode(ctx)`
  - `"spend"` → `domain_separator + "spend" + Encode(k) + Encode(ctx)`
  - `"refund"` → `domain_separator + "refund" + Encode(e) + Encode(t) + Encode(ctx)`

### 2. Proof Construction

**Current:**

- Manual sigma protocol construction
- Custom challenge/response computation
- Hand-rolled OR-proofs for range proof

**New Draft:**

- Uses `LinearRelation` to build proof statements
- Helper functions:
  - `append_pedersen(statement, P, Q, R)` - Pedersen proof
  - `append_dleq(statement, P, Q, X, Y)` - DLEQ proof
  - `append_range_proof(statement, H1, H2, H3, Com, L)` - Range proof
- `NISigmaProtocol.prove(witness, rng)` and `verify(pok)` for execution

**Example - Issuance Request:**

```typescript
// Current:
const kPrime = group.randomScalar();
const rPrime = group.randomScalar();
const K1 = group.msm([kPrime, rPrime], [params.H2, params.H3]);
const transcript = new SimpleTranscript('request');
transcript.addElement(K);
transcript.addElement(K1);
const gamma = transcript.getChallenge();
const kBar = kPrime.add(gamma.mul(k));
const rBar = rPrime.add(gamma.mul(r));

// New:
const statement = new LinearRelation(group);
appendPedersen(statement, H2, H3, K);
const sessionId = domainSeparator + 'request';
const prover = new NISigmaProtocol(sessionId, statement);
const pok = prover.prove([k, r], rng);
```

### 3. Range Proof

**Current (`spend.ts` lines 136-309):**

- CDS OR-proof construction
- For each bit j ∈ [0, L):
  - Proves `Com[j]` opens to either 0 or 1
  - Simulates one branch, proves the other
  - 2 first-round messages per bit
  - Complex challenge splitting: `γ₀[j] + γ₁[j] = γ`
- Proof contains: `gamma0[L]`, `z[L][2]`, `w00`, `w01`, etc.

**New Draft (algebraic approach):**

- Two equations per bit enforce binary constraint:
  1. **Opening**: `Com[j] = b[j]*H1 + s[j]*H3` (or with `kstar*H2` for j=0)
  2. **Binary constraint**: `Com[j] = b[j]*Com[j] + s2[j]*H3`
- Key insight: If `b[j] ≥ 2`, satisfying both requires knowing DL between H1 and H3
- Witness for bit j: `(b[j], s[j], s2[j])` where `s2[j] = (1-b[j])*s[j]`

**New witness structure:**

```
witness = [e, r2, r3, c, r,           // 5 scalars
           b[0..L-1],                  // L bit scalars
           s_com[0..L-1],              // L blinding scalars
           s2[0..L-1],                 // L derived scalars
           kstar, k2]                  // 2 scalars
// Total: 3L + 7 scalars
```

**Equations in new draft:**

1. BBS signature: `A_bar = e*(-A') + r2*B_bar`
2. Credential structure: `H1_prime = r3*B_bar + c*(-H1) + r*(-H3)`
   3-2+2L. Range proof (2 per bit)
   2L+3. Commitment consistency: `Com_total = c*H1 + kstar*H2 + sum(s_com[j]*2^j*H3)`

### 4. Wire Format

**Current (`cbor.ts`):**

- CBOR maps with string keys
- Example issuance request: `{"K": bytes, "gamma": bytes, "k_bar": bytes, "r_bar": bytes}`

**New Draft:**

- TLS presentation language (RFC 8446 Section 3)
- Fixed-size fields + variable-length with 2-byte length prefix
- Example issuance request:
  ```
  struct {
      opaque K[Ne];           /* 32 bytes */
      opaque pok<1..2^16-1>;  /* variable-length NISigmaProtocol proof */
  } IssuanceRequestMsg;
  ```

**Impact:**

- Remove `cbor2` dependency
- Implement TLS-style serialization
- `Ne = 32` (element size), `Ns = 32` (scalar size)
- Proof is opaque blob from NISigmaProtocol

### 5. Message Structure Changes

**Issuance Request:**

- Current: `{K, gamma, kBar, rBar}`
- New: `{K, pok}` where pok is NISigmaProtocol output

**Issuance Response:**

- Current: `{A, e, gammaResp, z, c, ctx}`
- New: `{A, e, c, pok}` (ctx derived from shared context)

**Spend Proof:**

- Current: `{k, s, ctx, APrime, BBar, Com, gamma, eBar, r2Bar, r3Bar, cBar, rBar, w00, w01, gamma0[], z[][], kBarFinal, sBarFinal}`
- New: `{k, s, ctx, A', B_bar, Com[], pok}`

**Refund:**

- Current: `{AStar, eStar, gamma, z, t}`
- New: `{A*, e*, t, pok}`

### 6. System Parameters

**Current:**

- `domain_separator` format not specified
- Generator derivation via `HashToGroup` with simple prefixes

**New Draft:**

- Structured domain separator: `"ACT-v1:" || org || ":" || service || ":" || deployment || ":" || version`
- Example: `"ACT-v1:example-corp:payment-api:production:2024-01-15"`
- Same generator derivation but with counter for collision avoidance

### 7. Error Handling

New error codes added:

- `InvalidIssuanceRequestProof`
- `InvalidIssuanceResponseProof`
- `InvalidClientSpendProof`
- `IdentityPointError`
- `InvalidRefundProof`
- `InvalidRefundAmount`
- `AmountTooBigError`
- `ScalarOutOfRangeError`

## Migration Plan

### Phase 1: Foundation

1. ✅ sigma-proofs package complete with LinearRelation and NISigmaProtocol
2. Add `append_pedersen`, `append_dleq` helper functions
3. Implement `append_range_proof` with algebraic approach

### Phase 2: ACT Core Refactor

1. Update params.ts with structured domain_separator
2. Replace transcript.ts with NISigmaProtocol usage
3. Refactor issuance.ts to use LinearRelation
4. Refactor spend.ts range proof to algebraic approach
5. Update types.ts with new proof structures

### Phase 3: Wire Format

1. Remove CBOR dependency
2. Implement TLS presentation language encoder/decoder
3. Update all message types

### Phase 4: Testing

1. Generate new test vectors with SeededPRNGForTestingOnly
2. Cross-validate with reference implementation (when available)

## Compatibility Notes

- **Breaking change**: Wire format completely different
- **Breaking change**: Proof structure different
- **Internal change**: Fiat-Shamir hashing (SHAKE128 vs BLAKE3)
- **Semantic change**: Domain separator format

## Resolved Questions

### 1. Test Vectors

**Decision**: Wait for Rust implementation to generate test vectors from `samschles/sigma-draft-compliance` branch.

Rust repo: https://github.com/SamuelSchlesinger/anonymous-credit-tokens/tree/samschles/sigma-draft-compliance

### 2. SeededPRNGForTestingOnly

`SeededPRNGForTestingOnly` is only needed for **test vector generation** (Appendix B of ACT draft). Protocol functions take `rng: PRNG` as parameter.

**Options for testing:**

- Rust test vectors include intermediate random values (preferred)
- Or implement JS `SeededPRNGForTestingOnly` using SHAKE128 (matches spec)

Our sigma-proofs already takes randomness as function input, so we can pass pre-generated values.

### 3. ctx (Request Context)

**Fully specified** in `draft-schlesinger-privacypass-act-01` Section 8.2:

```
request_context = concat(
    tokenChallenge.issuer_name,
    tokenChallenge.origin_info,
    tokenChallenge.credential_context,
    issuer_key_id
)
```

Key points:

- Derived from Privacy Pass `TokenChallenge` fields
- **Issuer determines** it during `IssueResponse`
- **Both parties can reconstruct** from shared TokenChallenge
- Used for domain separation (different origins/contexts → different credentials)
- `credential_context` field (0 or 32 bytes) enables:
  - Time-based expiration: `F(current_time_window)` where F is PRF
  - Per-application isolation

## Open Questions

1. **Error granularity**: New draft suggests single INVALID response externally - keep detailed internal errors?

## Reference Links

- ACT draft (sigma-compliance): https://github.com/SamuelSchlesinger/draft-act/tree/samschles/sigma-draft-compliance
- Rust impl (sigma-compliance): https://github.com/SamuelSchlesinger/anonymous-credit-tokens/tree/samschles/sigma-draft-compliance
- Privacy Pass ACT: https://datatracker.ietf.org/doc/draft-schlesinger-privacypass-act/
