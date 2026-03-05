# ACT Integration in privacypass-ts

Plan for adding ACT token type (0xE5AD) to privacypass-ts.

**Target:** thibmeu/privacypass-ts fork (feat/act branch) as submodule in this repo

**Specs:**

- draft-schlesinger-privacypass-act-01
- draft-schlesinger-cfrg-act-01
- draft-meunier-privacypass-reverse-flow-03

---

## Summary

Add ACT token type per draft-schlesinger-privacypass-act-01. Uses `act-ts` (TLS wire format, NISigmaProtocol proofs). No CBOR dependency.

---

## Repo Structure

```
act-ts/
  packages/
    sigma-proofs/           # Existing
    act-ts/                 # Existing (vnext)
    privacypass-ts/         # Submodule → thibmeu/privacypass-ts@feat/act
      src/
        act_token.ts        # NEW - ACT implementation
      package.json          # "act-ts": "workspace:*"
```

---

## Credential Flow

```
┌────────┐                              ┌────────┐                    ┌────────┐
│ Client │                              │ Origin │                    │ Issuer │
└───┬────┘                              └───┬────┘                    └───┬────┘
    │                                       │                             │
    │ ──────── Request ────────────────────>│                             │
    │ <─────── TokenChallenge + cost ───────│                             │
    │                                       │                             │
    │ ════════════════════ ISSUANCE (first time) ═════════════════════════│
    │                                       │                             │
    │ createTokenRequest()                  │                             │
    │ ─────────────────── TokenRequest ───────────────────────────────────>
    │ <──────────────────TokenResponse ────────────────────────────────────│
    │ finalizeCredential() → CredentialInfo │                             │
    │                                       │                             │
    │ ════════════════════ SPEND + REFUND (each request) ═════════════════│
    │                                       │                             │
    │ createSpendToken(cost)                │                             │
    │ ────── Request + Token ──────────────>│                             │
    │       (Authorization header)          │ verify spend proof          │
    │                                       │ issue refund                │
    │ <───── Response ─────────────────────│                             │
    │       (PrivacyPass-Reverse header)    │                             │
    │ processRefund()                       │                             │
    │ → credential updated with new balance │                             │
    │                                       │                             │
    │ ════════════════════ REPEAT until exhausted ════════════════════════│
```

---

## Token Type Entry

```typescript
export const ACT: TokenTypeEntry = {
  value: 0xe5ad,
  name: 'ACT (Ristretto255)',
  Nk: 0,
  Nid: 32,
  publicVerifiable: false,
  publicMetadata: false,
  privateMetadata: false,
};
```

---

## Client API

```typescript
class ACTClient implements PrivacyPassClient {
  private credentials: Map<string, CredentialState>;

  constructor(params: SystemParams);

  // --- PrivacyPassClient interface ---
  createTokenRequest(tokChl: ACTTokenChallenge, issuerPubKey: Uint8Array): Promise<ACTTokenRequest>;
  deserializeTokenResponse(bytes: Uint8Array): ACTTokenResponse;
  finalize(tokRes: ACTTokenResponse): Promise<Token>; // Throws: "Use finalizeCredential()"

  // --- ACT-specific ---
  finalizeCredential(tokRes: ACTTokenResponse): Promise<CredentialInfo>;
  createSpendToken(tokChl: ACTTokenChallenge, cost: bigint): ACTToken;
  processRefund(refundBytes: Uint8Array): void;

  // --- Inspection ---
  hasCredential(tokChl: ACTTokenChallenge): boolean;
  getBalance(tokChl: ACTTokenChallenge): bigint | undefined;

  // --- State persistence ---
  export(): ACTClientState;
  static import(state: ACTClientState): ACTClient;
  toJSON(): string;
  static fromJSON(json: string): ACTClient;

  // --- Internal ---
  private deriveKey(tokChl: ACTTokenChallenge): string; // sha256(issuer + origin + context)
}
```

---

## Types

```typescript
// Extended TokenChallenge (Section 7 of privacypass-act)
class ACTTokenChallenge extends TokenChallenge {
  credentialContext: Uint8Array; // 0 or 32 bytes
}

// HTTP challenge attributes (NOT wire format)
interface ACTChallengeParams {
  challenge: ACTTokenChallenge;
  tokenKey: Uint8Array;
  cost: bigint;
}

// Wire formats (using act-ts TLS encoding)
class ACTTokenRequest {
  tokenType: 0xe5ad;
  truncatedKeyId: number; // 1 byte (LSB of issuer_key_id)
  encodedRequest: Uint8Array; // encodeIssuanceRequest() from act-ts
}

class ACTTokenResponse {
  encodedResponse: Uint8Array; // encodeIssuanceResponse() from act-ts
}

class ACTToken {
  tokenType: 0xe5ad;
  challengeDigest: Uint8Array; // SHA-256(TokenChallenge), 32 bytes
  issuerKeyId: Uint8Array; // 32 bytes
  spendProof: Uint8Array; // encodeSpendProof() from act-ts
}

// Credential info returned from finalizeCredential
interface CredentialInfo {
  challenge: ACTTokenChallenge;
  balance: bigint;
}

// Internal state
type CredentialState =
  | { status: 'ready'; credential: CreditToken }
  | { status: 'spent'; state: SpendState; sentAt: Date }
  | { status: 'exhausted' };

// Persisted state
interface ACTClientState {
  version: number;
  credentials: Array<{ key: string; state: CredentialState }>;
}

// Error types
class ACTError extends Error {
  code: string;
}
class InsufficientBalanceError extends ACTError {
  available: bigint;
  requested: bigint;
}
class NoCredentialError extends ACTError {}
class CredentialInUseError extends ACTError {}
```

---

## Reverse Flow

Refund transmitted via `PrivacyPass-Reverse` HTTP header per draft-meunier-privacypass-reverse-flow-03.

```typescript
// Response header contains base64url-encoded GenericBatchTokenResponse
function parseReverseFlowResponse(header: string): { refund: Uint8Array };
```

---

## Media Types

```typescript
PRIVATE_CREDENTIAL_REQUEST = 'application/private-credential-request';
PRIVATE_CREDENTIAL_RESPONSE = 'application/private-credential-response';
```

---

## Design Decisions

| Decision          | Choice                                                                          |
| ----------------- | ------------------------------------------------------------------------------- |
| Credential key    | Tuple `(issuer, origin, context)` hashed via private `deriveKey()`              |
| Client model      | Credential store (multiple contexts per client)                                 |
| Concurrency       | Single-writer expected                                                          |
| Interface         | Implements `PrivacyPassClient`, `finalize()` throws, use `finalizeCredential()` |
| State persistence | Export/import pattern, user handles storage                                     |
| Reverse flow      | `PrivacyPass-Reverse` header with `GenericBatchTokenResponse` framing           |
| Wire format       | TLS presentation language via act-ts (no CBOR)                                  |
| Dependency        | Submodule + workspace dependency                                                |

---

## Setup

1. Remove `packages/privacypass-act` and all references
2. Add submodule:
   ```bash
   git submodule add -b feat/act git@github.com:thibmeu/privacypass-ts.git packages/privacypass-ts
   ```
3. Update root `package.json` workspaces:
   ```json
   {
     "workspaces": ["packages/sigma-proofs", "packages/act-ts", "packages/privacypass-ts"]
   }
   ```
4. Update `privacypass-ts/package.json`:
   ```json
   {
     "dependencies": {
       "act-ts": "workspace:*"
     }
   }
   ```

---

## Upstream Path

When upstreaming to cloudflare/privacypass-ts:

- Change `"act-ts": "workspace:*"` → `"act-ts": "^x.y.z"` (npm version)
- Everything else stays the same

---

## Out of Scope

- Issuer implementation (handled by privacypass-issuer)
- Nullifier tracking (handled by privacypass-origin)
- Key rotation (handled by privacypass-issuer)
- Credential storage persistence (user responsibility, export/import provided)

---

## Review Findings Summary

Panel review identified these priorities:

**P1 (High):**

- Define ACT-specific error classes
- Document Workers paid-tier-only (range proofs ~200ms for L=64)
- Credential size guidance for Durable Object storage

**P2 (Medium):**

- Make `createSpendToken` async (signals CPU cost)
- State schema versioning for migrations
- Atomic balance check in `createSpendToken`

---

## act-ts API Surface

Key exports from `act-ts`:

```typescript
// Types
export type { SystemParams, CreditToken, IssuanceState, SpendState, ... }

// Key generation
export { keyGen, derivePublicKey, publicKeyToBytes, publicKeyFromBytes }

// Issuance
export { issueRequest, issueResponse, verifyIssuance }

// Spending
export { proveSpend, verifySpendProof, issueRefund, constructRefundToken }

// TLS encoding (no CBOR)
export {
  encodeIssuanceRequest, decodeIssuanceRequest,
  encodeIssuanceResponse, decodeIssuanceResponse,
  encodeSpendProof, decodeSpendProof,
  encodeRefund, decodeRefund,
  encodeCreditToken, decodeCreditToken,
  encodeIssuanceState, decodeIssuanceState,
  encodeSpendState, decodeSpendState,
}
```
