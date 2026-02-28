# Agent Guidelines

**Generated:** 2026-02-28 | **Commit:** bef3dff | **Branch:** main

Instructions for AI agents working on this codebase.

---

## Project Overview

**act-ts** implements Anonymous Credit Tokens (ACT) and supporting cryptographic primitives in TypeScript. Target: browser, Cloudflare Workers, Node.js clients.

---

## Quick Reference

### Commands

```bash
npm test              # Vitest tests across all packages
npm run build         # Build all packages
npm run lint          # ESLint + Prettier check
npm run format        # Auto-fix lint/format issues
```

### Project Structure

```
act-ts/
  packages/
    sigma-proofs/       # Sigma protocols (109 tests) - COMPLETE
    act/                # ACT core (49 tests) - current draft
    privacypass-act/    # Privacy Pass integration - NOT STARTED
  docs/
    ARCHITECTURE.md     # Technical design
    VNEXT_MIGRATION.md  # Upcoming spec changes
    reviewers/          # Code review checklists
  AGENTS.md             # This file
```

---

## Specifications

| Package         | Spec                                                                                                               | Test Vectors                                                                                                                       |
| --------------- | ------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| sigma-proofs    | [draft-irtf-cfrg-sigma-protocols-01](https://www.ietf.org/archive/id/draft-irtf-cfrg-sigma-protocols-01.txt)       | [testSigmaProtocols.json](https://github.com/mmaker/draft-irtf-cfrg-sigma-protocols/blob/main/poc/vectors/testSigmaProtocols.json) |
| act             | [draft-schlesinger-cfrg-act-01](https://www.ietf.org/archive/id/draft-schlesinger-cfrg-act-01.txt)                 | Appendix A of spec                                                                                                                 |
| privacypass-act | [draft-schlesinger-privacypass-act-01](https://datatracker.ietf.org/doc/html/draft-schlesinger-privacypass-act-01) | TBD                                                                                                                                |

---

## Documentation

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Technical design, type system, protocol flows
- **[docs/VNEXT_MIGRATION.md](docs/VNEXT_MIGRATION.md)** - Migration plan for sigma-draft-compliance branch

---

## Code Reviews

Use specialized reviewer subagents for different perspectives:

| Command            | Persona                   | Focus                                         |
| ------------------ | ------------------------- | --------------------------------------------- |
| `/review-protocol` | IETF Security AD          | Spec compliance, security properties          |
| `/review-platform` | CF Distinguished Engineer | Production-readiness, runtime constraints     |
| `/review-crypto`   | Crypto Library Maintainer | Implementation quality, noble-curves patterns |
| `/review-api`      | ACT API Consumer          | Usability, ergonomics, integration            |

See [docs/reviewers/](docs/reviewers/) for detailed checklists.

---

## Code Style

- TypeScript strict mode
- No `any`, no non-null assertions
- Prefer `Uint8Array` over hex strings in APIs
- Use `@noble/curves` types directly where possible

---

## Git & Commits

- **Commit frequently**: After completing a logical unit of work, commit and push
- **Run tests first**: `npm test` must pass before committing
- **Message format**: `<type>: <short description>` (e.g., `feat: add SHAKE128 sponge`)
- **Types**: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`
- **No `--no-verify`**: Always let hooks run

---

## Boundaries

### Always

- **Test real behavior**: Every test must execute the code path it claims to test and verify correctness against known-good values or mathematical properties
- **Use spec test vectors** when available; cross-validate against reference implementations (Rust, Python/Sage)
- **Mark unsupported features as `it.todo()`** with explicit reason explaining what's needed
- **Run `npm test`** before considering any task complete
- **Reference specs** when implementing protocol logic; cite section numbers in comments

### Ask First

- Adding new dependencies beyond `@noble/curves` and `@noble/hashes`
- Deviating from IETF draft specifications
- Changing public API signatures
- Adding new ciphersuites

### Never

- **Fake, skip, or placeholder tests** for cryptographic code - this is security-critical software
- Use `any`, non-null assertions (`!`), or unsafe type casts (`as`)
- Commit code that doesn't pass `npm test`
- Implement cryptographic primitives from scratch when `@noble/*` provides them
- Skip serialization round-trip tests for wire formats

---

## Key Dependencies

| Package         | Purpose                                      |
| --------------- | -------------------------------------------- |
| `@noble/curves` | Ristretto255, P-256, scalar/point arithmetic |
| `@noble/hashes` | BLAKE3, SHA-512, SHAKE128                    |
| `cbor2`         | CBOR encoding for ACT wire format            |

---

## Where to Look

| Task | Location | Notes |
|------|----------|-------|
| Add group operation | `sigma-proofs/src/group.ts` | Implement Group interface |
| Add ciphersuite | `sigma-proofs/src/ciphersuites/` | See ristretto255.ts pattern |
| Modify proofs | `sigma-proofs/src/schnorr.ts` | LinearRelation + SchnorrProof |
| Fiat-Shamir | `sigma-proofs/src/fiat-shamir/` | Sponge, codec, NISigmaProtocol |
| ACT issuance | `act/src/issuance.ts` | Request/response/verify |
| ACT spending | `act/src/spend.ts` | Range proofs, refunds |
| Wire format | `act/src/cbor.ts` | Encode/decode messages |
| Test vectors | `*/test/vectors/` | JSON files from specs |

---

## Current Status

| Package | Status | Tests | Blocked By |
|---------|--------|-------|------------|
| sigma-proofs | Complete | 109 | - |
| act | Current draft | 49 | Waiting for new spec test vectors |
| privacypass-act | Placeholder | 0 | act vnext completion |

**Next milestone:** ACT migration to `sigma-draft-compliance` branch (see VNEXT_MIGRATION.md)
