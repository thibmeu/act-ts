# act

Anonymous Credit Tokens (ACT) core protocol in TypeScript.

**Specification:** [draft-schlesinger-cfrg-act-01](https://datatracker.ietf.org/doc/draft-schlesinger-cfrg-act/)

**Features:**

- Token issuance with BBS-style signatures
- Partial spending with range proofs
- Double-spend prevention via nullifiers
- Balance privacy (only spent amount revealed)

## Installation

```bash
npm install act
```

## Quick Start

```typescript
import {
  generateParams,
  generateKeyPair,
  issueRequest,
  issueResponse,
  verifyIssuance,
  proveSpend,
  verifyAndRefund,
  constructRefundToken,
  group,
} from 'act';

// 1. Setup
const domainSeparator = 'ACT-v1:example:api:prod:2024-01-15';
const params = generateParams(domainSeparator, 8); // 8-bit credits (0-255)
const { sk, pk } = generateKeyPair(params);
const ctx = group.randomScalar(); // application context

// 2. Issuance: Client requests credits
const [request, clientState] = issueRequest(params);
const response = issueResponse(params, sk, request, 100n, ctx);
const token = verifyIssuance(params, pk, request, response, clientState);
// token.c === 100n

// 3. Spending: Client spends some credits
const [proof, spendState] = proveSpend(params, token, 30n);

// 4. Verification & Refund: Issuer verifies and issues change
const nullifierDb = new Set<string>();
const refund = verifyAndRefund(params, sk, proof, nullifierDb, 0n);

// 5. Client constructs new token with remaining balance
const newToken = constructRefundToken(params, pk, proof, refund, spendState);
// newToken.c === 70n
```

## API Overview

### Setup

```typescript
// Generate system parameters
const params = generateParams(domainSeparator: string, L: number);
// L = bit length for credit values (max 2^L - 1 credits)

// Generate issuer key pair
const { sk, pk } = generateKeyPair(params);
```

### Issuance Protocol

```typescript
// Client: Create blinded request
const [request, state] = issueRequest(params);

// Issuer: Create signed response
const response = issueResponse(params, sk, request, credits, ctx);

// Client: Verify and extract token
const token = verifyIssuance(params, pk, request, response, state);
```

### Spending Protocol

```typescript
// Client: Create spend proof
const [proof, spendState] = proveSpend(params, token, amount);

// Issuer: Verify proof and issue refund
const refund = verifyAndRefund(params, sk, proof, nullifierDb, returnAmount);

// Client: Construct new token from refund
const newToken = constructRefundToken(params, pk, proof, refund, spendState);
```

### Wire Format

```typescript
import { encodeIssuanceRequest, decodeIssuanceRequest, ... } from 'act';

// Serialize for transmission
const bytes = encodeIssuanceRequest(request);
const decoded = decodeIssuanceRequest(bytes);
```

## Protocol Flow

```
Client                                    Issuer
  |                                         |
  |-- IssueRequest (K, proof) ------------->|
  |                                         |
  |<-- IssueResponse (A, e, c, proof) ------|
  |                                         |
  | [Client verifies and stores token]      |
  |                                         |
  |-- SpendProof (k, s, A', B_bar, ...) --->|
  |                                         |
  |<-- Refund (A*, e*, t, proof) -----------|
  |                                         |
  | [Client constructs new token]           |
```

## Security Properties

- **Unlinkability**: Issuance cannot be linked to spending (information-theoretic)
- **Unforgeability**: Cannot spend more credits than issued (q-SDH assumption)
- **Double-Spend Prevention**: Nullifiers prevent token reuse
- **Balance Privacy**: Only spent amount revealed, not total balance

## Ciphersuite

**ACT(ristretto255, BLAKE3)** - Current implementation

- Group: Ristretto255 (RFC 9496)
- Hash: BLAKE3 for Fiat-Shamir
- Encoding: CBOR

**ACT(ristretto255, SHAKE128)** - Upcoming (sigma-draft-compliance)

- Uses sigma-proofs package for proofs
- TLS presentation language encoding

## Limitations

- **Not quantum-resistant**: Based on discrete logarithm
- **Issuer trust**: Issuer can decline refunds (by design for revocation)
- **Sequential spending**: Each spend requires refund before next spend

## Security Considerations

### Memory Zeroization

JavaScript/TypeScript cannot guarantee memory zeroization. Secret material (blinding factors, private keys, credential data) may persist in memory after use until garbage collected. This is an inherent platform limitation.

**Mitigations:**

- Minimize credential lifetime in memory
- Use secure enclaves for high-security deployments
- Consider WebAssembly with explicit memory management for sensitive operations

### Timing Side-Channels

The implementation delegates cryptographic operations to `@noble/curves`, which provides constant-time scalar and point arithmetic. However:

- JavaScript bigint operations may not be constant-time
- Garbage collection timing may leak information
- JIT compilation behavior is unpredictable

For high-assurance deployments, consider native implementations.

### State Export

The `export()` / `import()` functions for client state serialize credential secrets in plaintext. Callers must encrypt exported state before storage or transmission.

## Development

```bash
npm test        # Run tests
npm run build   # Build package
```

## Related

- [sigma-proofs](../sigma-proofs) - Underlying proof system
- [privacypass-act](../privacypass-act) - Privacy Pass integration

## License

Apache-2.0
