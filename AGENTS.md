# Agent Guidelines

**Generated:** 2026-03-06 | **Commit:** 3e25298 | **Branch:** main

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

| Directory                  | Purpose                             |
| -------------------------- | ----------------------------------- |
| `packages/sigma-proofs/`   | Sigma protocols (123 tests)         |
| `packages/act-ts/`         | ACT core (86 tests)                 |
| `packages/privacypass-ts/` | Privacy Pass integration (96 tests) |
| `docs/ARCHITECTURE.md`     | Technical design                    |

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for system design details.

---

## Specifications

| Package      | Spec                                                                                                    |
| ------------ | ------------------------------------------------------------------------------------------------------- |
| sigma-proofs | [draft-irtf-cfrg-sigma-protocols-01](https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/) |
| act-ts       | [draft-schlesinger-cfrg-act-01](https://datatracker.ietf.org/doc/draft-schlesinger-cfrg-act/)           |

---

## Where to Look

| Task             | Location                                                 |
| ---------------- | -------------------------------------------------------- |
| Group operations | `packages/sigma-proofs/src/ciphersuites/ristretto255.ts` |
| BLS12-381        | `packages/sigma-proofs/src/ciphersuites/bls12-381.ts`    |
| Schnorr proofs   | `packages/sigma-proofs/src/schnorr.ts`                   |
| Fiat-Shamir      | `packages/sigma-proofs/src/fiat-shamir/`                 |
| Test DRNG        | `packages/sigma-proofs/src/test-drng.ts`                 |
| ACT issuance     | `packages/act-ts/src/issuance.ts`                        |
| ACT spending     | `packages/act-ts/src/spend.ts`                           |
| Range proofs     | `packages/act-ts/src/spend.ts:buildSpendRelation()`      |
| TLS encoding     | `packages/act-ts/src/encoding.ts`                        |
| System params    | `packages/act-ts/src/params.ts`                          |

---

## Code Style

- **TypeScript strict** with `noUncheckedIndexedAccess`
- Prefer `Uint8Array` over hex strings
- Use `@noble/curves` types directly
- Commit format: `<type>: <desc>` (feat/fix/refactor/test/docs/chore)

---

## Boundaries

**Always:**

- Run `npm test` before commits
- Use spec test vectors when available
- Reference spec section numbers in comments
- Mark unsupported features as `it.todo()` with reason

**Ask first:**

- New dependencies beyond `@noble/*`
- Deviating from IETF drafts
- Changing public API
- Adding ciphersuites

**Never:**

- Use `any`, `!`, or `as` casts
- Fake/placeholder tests for crypto code
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

## Gotchas

- **Fiat-Shamir transcript**: Our SHAKE128 sponge differs from Rust POC; spec vector interop blocked
- **Domain separator**: Takes `string | Uint8Array`, prefer string format `ACT-v1:org:service:deployment:version`
- **L parameter**: Bit length for credit values, must be 1-128
- **Scalar creation**: Use `group.scalarFromBigint()`, not `group.hashToScalar()` for context binding

---

## Dependencies

| Package         | Purpose                                          |
| --------------- | ------------------------------------------------ |
| `@noble/curves` | Ristretto255, P-256, BLS12-381, scalar/point ops |
| `@noble/hashes` | SHAKE128, SHA-512                                |
| `fast-check`    | Property-based testing                           |
