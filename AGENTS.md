# Agent Guidelines

**Generated:** 2026-03-05 | **Commit:** bb967d0 | **Branch:** main

Anonymous Credit Tokens (ACT) + sigma protocols in TypeScript. Targets: browser, Cloudflare Workers, Node.js.

---

## Commands

```bash
npm test              # Vitest (all packages)
npm run build         # tsup + tsc
npm run lint          # ESLint + Prettier
npm run format        # Auto-fix
```

---

## Structure

```
packages/
  sigma-proofs/       # Sigma protocols (119 tests)
    src/fiat-shamir/  # SHAKE128 sponge, NISigmaProtocol
    src/ciphersuites/ # ristretto255, P-256, BLS12-381
  act-ts/             # ACT core (121 tests)
    src/              # Main API (v0.1.0)
  privacypass-ts/     # Privacy Pass integration (96 tests)
docs/
  ARCHITECTURE.md     # Technical design
```

---

## Specifications

| Package      | Spec                                                                                                         | Notes                  |
| ------------ | ------------------------------------------------------------------------------------------------------------ | ---------------------- |
| sigma-proofs | [draft-irtf-cfrg-sigma-protocols-01](https://www.ietf.org/archive/id/draft-irtf-cfrg-sigma-protocols-01.txt) | Complete               |
| act-ts       | [draft-schlesinger-cfrg-act-01](https://www.ietf.org/archive/id/draft-schlesinger-cfrg-act-01.txt)           | Algebraic range proofs |

---

## Where to Look

| Task             | Location                                                |
| ---------------- | ------------------------------------------------------- |
| Group operations | `sigma-proofs/src/ciphersuites/ristretto255.ts`         |
| BLS12-381        | `sigma-proofs/src/ciphersuites/bls12-381.ts`            |
| Schnorr proofs   | `sigma-proofs/src/schnorr.ts`                           |
| Fiat-Shamir      | `sigma-proofs/src/fiat-shamir/sponge.ts`, `ni-sigma.ts` |
| Test DRNG        | `sigma-proofs/src/test-drng.ts`                         |
| ACT issuance     | `act-ts/src/issuance.ts`                                |
| ACT spending     | `act-ts/src/spend.ts`                                   |
| Range proofs     | `act-ts/src/spend.ts:buildSpendRelation()`              |
| TLS encoding     | `act-ts/src/encoding.ts`                                |
| System params    | `act-ts/src/params.ts`                                  |

---

## Code Style

- **TypeScript strict** with `noUncheckedIndexedAccess`
- **No `any`**, no `!` assertions, no `as Type` casts
- Prefer `Uint8Array` over hex strings
- Use `@noble/curves` types directly
- Commit format: `<type>: <desc>` (feat/fix/refactor/test/docs/chore)

---

## Boundaries

### Always

- Run `npm test` before commits
- Use spec test vectors when available
- Reference spec section numbers in comments
- Mark unsupported features as `it.todo()` with reason

### Ask First

- New dependencies beyond `@noble/*`
- Deviating from IETF drafts
- Changing public API
- Adding ciphersuites

### Never

- Fake/placeholder tests for crypto code
- `any`, `!`, or `as` casts
- Commit failing tests
- Implement crypto primitives when `@noble/*` provides them

---

## Test Patterns

- **Vector files**: `test/vectors/*.json` from IETF specs
- **Roundtrip tests**: Required for all serialization
- **Property tests**: `fast-check` for encodings
- **Parameterized**: Same tests run across ristretto255, P-256, BLS12-381
- **`it.todo()`**: For blocked features with reason

---

## Current Status

| Package        | Status   | Tests |
| -------------- | -------- | ----- |
| sigma-proofs   | v0.1.0   | 119   |
| act-ts         | v0.1.0   | 121   |
| privacypass-ts | Complete | 96    |

### What's Done

- SHAKE128 Fiat-Shamir (draft-irtf-cfrg-fiat-shamir-01)
- SHAKE128 sponge verified against spec vectors
- BLS12-381 G1 ciphersuite
- Algebraic range proofs
- TLS wire format
- Horner optimization for `pow2WeightedSum()`
- TestDRNGForTestingOnly for deterministic proofs
- Optional RNG injection for proverCommit/prove/proveBatchable

### Blocked

- Spec test vector interop: Fiat-Shamir transcript mismatch with POC
- Rust reference interop: Needs alignment

---

## Key Dependencies

| Package         | Purpose                                          |
| --------------- | ------------------------------------------------ |
| `@noble/curves` | Ristretto255, P-256, BLS12-381, scalar/point ops |
| `@noble/hashes` | SHAKE128, SHA-512                                |
| `fast-check`    | Property-based testing                           |
