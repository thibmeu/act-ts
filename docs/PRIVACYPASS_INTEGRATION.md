# ACT Integration in cloudflare/privacypass-ts

Plan for adding ACT token type (0xE5AD) to cloudflare/privacypass-ts.

**Specs:**

- draft-schlesinger-privacypass-act-01
- draft-schlesinger-cfrg-act-01
- draft-meunier-privacypass-reverse-flow-03

---

## Summary

Add ACT token type per draft-schlesinger-privacypass-act-01. Depends on `act` as peer dependency. Wait for sigma-draft-compliance completion before implementation.

---

## Package Changes

```
cloudflare/privacypass-ts/
  src/
    act_token.ts    # NEW
    index.ts        # Add TOKEN_TYPES.ACT, export act namespace
  package.json      # Add peerDep: act
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

// Wire formats
class ACTTokenRequest {
  tokenType: 0xe5ad;
  truncatedKeyId: number; // 1 byte (LSB of issuer_key_id)
  encodedRequest: Uint8Array; // IssuanceRequest from act
}

class ACTTokenResponse {
  encodedResponse: Uint8Array; // IssuanceResponse from act
}

class ACTToken {
  tokenType: 0xe5ad;
  challengeDigest: Uint8Array; // SHA-256(TokenChallenge), 32 bytes
  issuerKeyId: Uint8Array; // 32 bytes
  spendProof: Uint8Array; // SpendProof from act
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

---

## Blockers Before Implementation

| Blocker                             | Status      |
| ----------------------------------- | ----------- |
| sigma-draft-compliance in act       | In progress |
| Fix `Buffer.from()` in spend.ts:654 | TODO        |
| Add consumed flags to state types   | TODO        |
| Improve CBOR error handling         | TODO        |

---

## Out of Scope

- Issuer implementation (handled by privacypass-issuer)
- Nullifier tracking (handled by privacypass-origin)
- Key rotation (handled by privacypass-issuer)
- Credential storage persistence (user responsibility, export/import provided)

---

## Review Findings Summary

Panel review identified these priorities:

**P0 (Blockers for act):**

- Fix `Buffer.from()` → `bytesToHex()` in spend.ts (Workers crash)
- Context must use `hashToScalar(concat(...))`
- Add consumed flags to prevent state reuse

**P1 (High):**

- Define ACT-specific error classes
- Document Workers paid-tier-only (range proofs ~200ms)
- Credential size guidance for Durable Object storage

**P2 (Medium):**

- Make `createSpendToken` async (signals CPU cost)
- State schema versioning for migrations
- Atomic balance check in `createSpendToken`
