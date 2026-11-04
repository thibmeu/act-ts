# Agent Guidelines

**Updated:** 2026-11-04

EC-ACT (Anonymous Credit Tokens) + sigma protocols in TypeScript, P-256, interoperable with act-rs. Targets: browser, Cloudflare Workers, Node.js.

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

| Directory                | Purpose                     |
| ------------------------ | --------------------------- |
| `packages/sigma-proofs/` | Sigma protocols (106 tests) |
| `packages/act-ts/`       | EC-ACT (34 tests)           |
| `docs/ARCHITECTURE.md`   | Technical design            |

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for system design details.

---

## Specifications

| Package      | Spec                                                                                                                                                                                                              |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| sigma-proofs | [draft-irtf-cfrg-sigma-protocols-03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/03/), [fiat-shamir-03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/03/)                    |
| act-ts       | [draft-schlesinger-mole-ec-act-00](https://datatracker.ietf.org/doc/draft-schlesinger-mole-ec-act/), group functions from [draft-ladd-mole-ec-ihat-00](https://datatracker.ietf.org/doc/draft-ladd-mole-ec-ihat/) |
| reference    | [act-rs](https://github.com/Moderation-of-unLinkable-Endorsements/act-rs)                                                                                                                                         |

---

## Where to Look

| Task                    | Location                                                         |
| ----------------------- | ---------------------------------------------------------------- |
| Relations, prove/verify | `packages/sigma-proofs/src/linear-relation.ts`, `fiat-shamir.ts` |
| Codecs, ciphersuites    | `packages/sigma-proofs/src/ciphersuites.ts`                      |
| Hash/derive (EC-IHAT)   | `packages/act-ts/src/group.ts`                                   |
| Protocol                | `packages/act-ts/src/act.ts`                                     |
| Spend relation          | `packages/act-ts/src/act.ts:spendRelation()`                     |
| Wire encodings          | `packages/act-ts/src/wire.ts`                                    |

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
- **Parameterized**: sigma-proofs tests run across P-256 and BLS12-381
- **`it.todo()`**: For blocked features with reason

---

## Gotchas

- **Sigma revision**: EC-ACTv1 pins sigma-protocols/fiat-shamir **-03**; -04 changes `SerializeLinearRelation` and needs a new ciphersuite ID.
- **ctx_proto**: spec is `EC-ACTv1-P256-SHA256`; act-rs still uses `ACTv1-P256-SHA256` (pass `protocolContext` to interoperate). Both vector sets are tested.
- **Relation layout**: element/scalar order of the Relation blocks is wire-relevant; vectors pin it.
- **noble `multiply(0n)` throws**: use `mulSmall` (amounts, bits) or rely on `commit`'s `(k+1)P - P`.
- **L**: balance width, 1..64; amounts are `bigint`.
- **Effects**: protocol code is written once as generators yielding multiplication batches; `runSync` (noble) and `runAsync` (WebCrypto) drive them. Put every multiplication in a batch (`mulAll`), not inline.
- **Secret scalars in batches**: never dedupe, cache, or special-case them by value (zero, equality); the import count must not depend on secrets (tested).

---

## Dependencies

| Package         | Purpose                              |
| --------------- | ------------------------------------ |
| `@noble/curves` | P-256, BLS12-381, hash-to-curve, MSM |
| `@noble/hashes` | SHAKE128, SHA-256                    |
| `fast-check`    | Property-based testing               |
