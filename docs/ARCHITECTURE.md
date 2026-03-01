# Architecture

Technical design of act-ts packages.

---

## Package Overview

```
packages/
  sigma-proofs/       # draft-irtf-cfrg-sigma-protocols-01
  act-ts/             # draft-schlesinger-cfrg-act-01
  privacypass-act/    # draft-schlesinger-privacypass-act-01
```

Dependency graph: `privacypass-act` → `act-ts` → `sigma-proofs`

---

## Sigma Proofs

Implements LinearRelation-based API from draft-irtf-cfrg-sigma-protocols-01.

### Core Types

| Type                | Purpose                                                           |
| ------------------- | ----------------------------------------------------------------- |
| `LinearMap`         | Sparse matrix (Yale/CSR format) for efficient coefficient storage |
| `LinearCombination` | Single row of LinearMap; `sum(coeff_i * var_i)`                   |
| `LinearRelation`    | Constraint system builder; manages scalar/element allocation      |
| `SchnorrProof`      | Sigma protocol: commit → challenge → respond → verify             |

### Constraint System

```typescript
// Proving knowledge of x such that Y = x·G
const relation = new LinearRelation(suite);
const [x] = relation.allocate_scalars(1); // witness
const [Y] = relation.allocate_elements([Y]); // public
relation.append_equation(
  new LinearCombination([[x, 1n]]), // x
  [[0, G]] // G (generator at index 0)
);
```

### Ciphersuites

| Suite        | Curve      | Hash       | Use               |
| ------------ | ---------- | ---------- | ----------------- |
| P256         | NIST P-256 | SHA-512    | Spec test vectors |
| Ristretto255 | Curve25519 | Blake3 XOF | ACT protocol      |

---

## ACT

Anonymous Credit Tokens per draft-schlesinger-cfrg-act-01.

### Protocol Flow

```
┌─────────┐                          ┌─────────┐
│  Client │                          │  Issuer │
└────┬────┘                          └────┬────┘
     │                                    │
     │ ─────── PreIssuance.new() ──────►  │
     │                                    │
     │ ◄─────── (internal state) ───────  │
     │                                    │
     │ ─────── IssuanceRequest ─────────► │
     │         (with proof of knowledge)  │
     │                                    │
     │ ◄────── IssuanceResponse ───────── │
     │         (with proof of correctness)│
     │                                    │
     │ ─────── CreditToken.finalize() ──► │
     │                                    │
     │ ��────── SpendProof ──────────────► │
     │         (with range proof)         │
     │                                    │
```

### Key Types

| Type               | Role                                           |
| ------------------ | ---------------------------------------------- |
| `PreIssuance`      | Client-side state before request               |
| `IssuanceRequest`  | Blinded request + proof of knowledge of (k, r) |
| `IssuanceResponse` | Issuer signature + proof of correctness        |
| `CreditToken`      | Unblinded token with credit value              |
| `SpendProof`       | Proof of valid spend (amount ≤ balance)        |
| `PreRefund`        | State for partial refund                       |
| `Refund`           | New token with remaining balance               |

### Sigma Proof Integration

ACT uses sigma proofs for:

1. **Issuance Request**: Knowledge of blinding factors (k, r)
2. **Issuance Response**: BBS+ signature computed correctly
3. **Spend Proof**: Range proof via binary decomposition
4. **Refund Proof**: New token derived correctly from old

---

## PrivacyPass-ACT

HTTP binding per draft-schlesinger-privacypass-act-01.

### Token Types

Extends PrivacyPass with ACT-specific token types:

- Token type 0x0004: ACT issuance
- Token type 0x0005: ACT redemption

### CBOR Serialization

All wire formats use CBOR (RFC 8949) per spec.

---

## Security Considerations

### Constant-Time Caveat

From noble-curves documentation:

> "JIT-compiler and Garbage Collector make 'constant time' extremely hard to achieve in JS."

This implementation is for **demonstration and interoperability testing**, not high-security production deployment without a native cryptographic backend.

### Sensitive Material

- Scalars (private keys, blinding factors) should be zeroed after use where possible
- Error messages must not leak sensitive values
- Timing of error paths should not vary based on secret data

---

## Performance

### Implemented Optimizations (T1+T2)

- **T1.1**: Memoized `getInstanceLabel()` in LinearRelation
- **T1.2**: H3 power doubling chain (L-1 doublings vs L scalar muls)
- **T1.3**: Pre-sized arrays in `proveSpend`
- **T2.1**: Cached one/zero scalars per group via WeakMap
- **T2.2**: Pre-convert bit arrays to scalar arrays

Results for L=64: proveSpend +12%, verifySpend +13%, full flow +39%.

### Evaluated but Not Implemented

- **Batch LinearMap MSMs**: Standard Pippenger returns single sum, not per-equation results. Would require deep @noble/curves modifications.
- **Precomputed tables for H1-H4**: Tested with `RistrettoPoint.precompute()`. Only ~5% speedup on scalar multiply, and ACT only does one H1.multiply per proof. Most H* usage is via MSM which doesn't benefit from per-point precompute.

---

## Dependencies

| Package         | Purpose                                      |
| --------------- | -------------------------------------------- |
| `@noble/curves` | Ristretto255, P-256, scalar/point arithmetic |
| `@noble/hashes` | Blake3 (XOF), SHA-512                        |
