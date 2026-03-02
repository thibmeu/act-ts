# ACT Migration: vnext → main

vnext implementation complete. Final step: promote vnext to main API.

## Migration Steps

1. **Delete old files:**

   - `cbor.ts` - CBOR encoding
   - `transcript.ts` - BLAKE3 transcript
   - `issuance.ts` - old issuance
   - `spend.ts` - CDS OR-proofs
   - `params.ts` - old params
   - `keygen.ts` - old keygen
   - `types.ts` - old types
   - `index.ts` - old exports

2. **Rename vnext files** (remove `-vnext` suffix):

   - `encoding-vnext.ts` → `encoding.ts`
   - `issuance-vnext.ts` → `issuance.ts`
   - `keygen-vnext.ts` → `keygen.ts`
   - `params-vnext.ts` → `params.ts`
   - `spend-vnext.ts` → `spend.ts`
   - `types-vnext.ts` → `types.ts`
   - `index-vnext.ts` → `index.ts`

3. **Update index.ts:**

   - Re-export group types from `sigma-proofs` (delete `group.ts`)
   - Update import paths (remove `-vnext`)

4. **Update tests:**

   - Change imports from `act-ts/vnext` to `act-ts`

5. **Update privacypass-ts:**

   - Change imports from `act-ts/vnext` to `act-ts`

6. **Remove dependencies:**
   - `cbor2` from package.json

## Breaking Changes

| Area        | Old                            | New                               |
| ----------- | ------------------------------ | --------------------------------- |
| Wire format | CBOR maps                      | TLS presentation language         |
| Hash        | BLAKE3                         | SHAKE128                          |
| Range proof | CDS OR-proofs (2L simulations) | Algebraic binary constraints      |
| Fiat-Shamir | Custom transcript              | NISigmaProtocol from sigma-proofs |

## Reference

- ACT spec: https://www.ietf.org/archive/id/draft-schlesinger-cfrg-act-01.txt
- Sigma protocols: https://www.ietf.org/archive/id/draft-irtf-cfrg-sigma-protocols-01.txt
