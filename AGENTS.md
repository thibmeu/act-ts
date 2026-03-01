# Agent Guidelines

**Generated:** 2026-03-01 | **Commit:** 0c70498 | **Branch:** main

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
  sigma-proofs/       # Sigma protocols (112 tests) - COMPLETE
    src/fiat-shamir/  # SHAKE128 sponge, NISigmaProtocol
    src/ciphersuites/ # ristretto255, P-256
  act-ts/             # ACT core (124 tests) - vnext active
    src/*-vnext.ts    # New API (use these)
    src/*.ts          # Old API (deprecated)
  privacypass-act/    # NOT STARTED
docs/
  ARCHITECTURE.md     # Technical design
  VNEXT_MIGRATION.md  # Migration notes
  reviewers/          # Review checklists
```

---

## Specifications

| Package         | Spec                                                                                                               | Notes                             |
| --------------- | ------------------------------------------------------------------------------------------------------------------ | --------------------------------- |
| sigma-proofs    | [draft-irtf-cfrg-sigma-protocols-01](https://www.ietf.org/archive/id/draft-irtf-cfrg-sigma-protocols-01.txt)       | Complete                          |
| act-ts          | [draft-schlesinger-cfrg-act-01](https://www.ietf.org/archive/id/draft-schlesinger-cfrg-act-01.txt)                 | vnext uses algebraic range proofs |
| privacypass-act | [draft-schlesinger-privacypass-act-01](https://datatracker.ietf.org/doc/html/draft-schlesinger-privacypass-act-01) | Blocked                           |

---

## Where to Look

| Task             | Location                                                |
| ---------------- | ------------------------------------------------------- |
| Group operations | `sigma-proofs/src/ciphersuites/ristretto255.ts`         |
| Schnorr proofs   | `sigma-proofs/src/schnorr.ts`                           |
| Fiat-Shamir      | `sigma-proofs/src/fiat-shamir/sponge.ts`, `ni-sigma.ts` |
| ACT issuance     | `act-ts/src/issuance-vnext.ts`                          |
| ACT spending     | `act-ts/src/spend-vnext.ts`                             |
| Range proofs     | `act-ts/src/spend-vnext.ts:buildSpendRelation()`        |
| TLS encoding     | `act-ts/src/encoding-vnext.ts`                          |
| System params    | `act-ts/src/params-vnext.ts`                            |

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
- **Parameterized**: Same tests run across ristretto255, P-256
- **`it.todo()`**: For unsupported features (e.g., BLS12-381)

---

## Current Status

| Package         | Status       | Tests           |
| --------------- | ------------ | --------------- |
| sigma-proofs    | Complete     | 112             |
| act-ts          | vnext active | 124             |
| privacypass-act | Not started  | 1 (placeholder) |

### What's Done (vnext)

- SHAKE128 Fiat-Shamir (draft-irtf-cfrg-fiat-shamir-01)
- Algebraic range proofs (replacing CDS OR-proofs)
- TLS wire format (replacing CBOR)
- Horner optimization for `pow2WeightedSum()`

### Known Issues

- Small L values (1,2,3) fail in spend proofs
- Test vectors incomplete (waiting on spec)
- `Buffer.from()` usage in spend.ts needs fix

### Blocked

- privacypass-act: Needs act-ts vnext completion
- Interop testing: Needs Rust reference alignment

---

## Key Dependencies

| Package         | Purpose                               |
| --------------- | ------------------------------------- |
| `@noble/curves` | Ristretto255, P-256, scalar/point ops |
| `@noble/hashes` | SHAKE128, SHA-512                     |
| `cbor2`         | CBOR encoding (old API)               |
| `fast-check`    | Property-based testing                |

---

## Panel Reviews

| Persona                   | Focus                                     |
| ------------------------- | ----------------------------------------- |
| IETF Security AD          | Spec compliance, security properties      |
| CF Distinguished Engineer | Production-readiness, Workers constraints |
| Crypto Library Maintainer | noble-curves patterns, constant-time      |
| ACT API Consumer          | Usability, ergonomics                     |

See `docs/reviewers/` for checklists.
