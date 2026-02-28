# act-ts: Anonymous Credit Tokens in TypeScript

TypeScript implementation of Anonymous Credit Tokens (ACT) for privacy-preserving credit systems.

**Specification:** Implements [draft-schlesinger-cfrg-act](https://datatracker.ietf.org/doc/draft-schlesinger-cfrg-act/) and [draft-schlesinger-privacypass-act](https://datatracker.ietf.org/doc/draft-schlesinger-privacypass-act/).

**Target Environments:** Browser, Cloudflare Workers, Node.js

## Packages

| Package | Description | Spec |
|---------|-------------|------|
| [sigma-proofs](./packages/sigma-proofs) | Sigma protocols for zero-knowledge proofs | [draft-irtf-cfrg-sigma-protocols-01](https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/) |
| [act](./packages/act) | Anonymous Credit Tokens core protocol | [draft-schlesinger-cfrg-act-01](https://datatracker.ietf.org/doc/draft-schlesinger-cfrg-act/) |
| [privacypass-act](./packages/privacypass-act) | Privacy Pass integration for ACT | [draft-schlesinger-privacypass-act-01](https://datatracker.ietf.org/doc/draft-schlesinger-privacypass-act/) |

## What is ACT?

Anonymous Credit Tokens enable privacy-preserving credit systems where:

- **Unlinkability**: Issuer cannot link credit issuance to spending, or connect multiple transactions
- **Partial Spending**: Spend any amount up to balance, receive anonymous change
- **Double-Spend Prevention**: Cryptographic nullifiers ensure each token is used only once
- **Balance Privacy**: Only the spent amount is revealed, not total balance

### Use Cases

- **Rate Limiting**: Issue daily allowances that clients spend anonymously
- **API Credits**: Pre-paid API access without tracking individual request patterns
- **Privacy Proxies**: Session-based access control with concurrency enforcement

## Installation

```bash
# Install individual packages
npm install sigma-proofs
npm install act
npm install privacypass-act
```

## Quick Example

```typescript
import { generateParams, generateKeyPair, issueRequest, issueResponse, verifyIssuance, proveSpend, verifyAndRefund, constructRefundToken } from 'act';

// Setup
const params = generateParams('ACT-v1:example:api:prod:2024-01-15', 8);
const { sk, pk } = generateKeyPair(params);

// Issuance: Client requests 100 credits
const [request, clientState] = issueRequest(params);
const response = issueResponse(params, sk, request, 100n, ctx);
const token = verifyIssuance(params, pk, request, response, clientState);

// Spending: Client spends 30 credits
const [proof, spendState] = proveSpend(params, token, 30n);
const refund = verifyAndRefund(params, sk, proof, nullifierDb, 0n);
const newToken = constructRefundToken(params, pk, proof, refund, spendState);
// newToken has 70 credits remaining
```

## Development

| Task | Command |
|------|---------|
| Install | `npm install` |
| Build | `npm run build` |
| Test | `npm test` |
| Lint | `npm run lint` |
| Format | `npm run format` |

### Project Structure

```
packages/
  sigma-proofs/     # Zero-knowledge proof primitives
  act/              # Core ACT protocol
  privacypass-act/  # Privacy Pass integration
docs/
  ARCHITECTURE.md   # Technical design
  VNEXT_MIGRATION.md # Upcoming spec changes
```

## Status

| Package | Status | Tests |
|---------|--------|-------|
| sigma-proofs | Complete | 109 passing |
| act | Current draft implemented | 49 passing |
| privacypass-act | Not started | - |

### Roadmap

- [x] sigma-proofs: LinearRelation, SchnorrProof, NISigmaProtocol
- [x] act: Issuance, spending, range proofs (current draft)
- [ ] act: Migration to sigma-draft-compliance (pending test vectors)
- [ ] privacypass-act: Token challenge/response integration

## Related Projects

- [anonymous-credit-tokens](https://github.com/AquilaCrypto/anonymous-credit-tokens) - Rust reference implementation
- [privacypass-ts](https://github.com/cloudflare/privacypass-ts) - Privacy Pass TypeScript library

## License

[Apache-2.0](LICENSE)
