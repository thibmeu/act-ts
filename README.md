# act-ts: Anonymous Credit Tokens in TypeScript

> **Warning**
> This software is experimental and has not been audited. The underlying cryptographic specifications are IETF drafts subject to change. Use at your own risk.

TypeScript implementation of Anonymous Credit Tokens (ACT) for privacy-preserving credit systems.

**Specification:** Implements [draft-schlesinger-cfrg-act](https://datatracker.ietf.org/doc/draft-schlesinger-cfrg-act/) and [draft-schlesinger-privacypass-act](https://datatracker.ietf.org/doc/draft-schlesinger-privacypass-act/).

**Target Environments:** Browser, Cloudflare Workers, Node.js

## Table of Contents

- [Packages](#packages)
- [What is ACT?](#what-is-act)
- [Installation](#installation)
- [Quick Example](#quick-example)
- [Development](#development)
- [Security Considerations](#security-considerations)
- [Related Projects](#related-projects)
- [License](#license)

## Packages

| Package                                 | Description                               | Spec                                                                                                    |
| --------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| [sigma-proofs](./packages/sigma-proofs) | Sigma protocols for zero-knowledge proofs | [draft-irtf-cfrg-sigma-protocols-01](https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/) |
| [act-ts](./packages/act-ts)             | Anonymous Credit Tokens core protocol     | [draft-schlesinger-cfrg-act-01](https://datatracker.ietf.org/doc/draft-schlesinger-cfrg-act/)           |

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
npm install act-ts
```

## Quick Example

```typescript
import {
  ristretto255,
  generateParameters,
  keyGen,
  issueRequest,
  issueResponse,
  verifyIssuance,
  proveSpend,
  verifyAndRefund,
  constructRefundToken,
  SeededPRNG,
} from 'act-ts';

// Setup (vnext API)
const group = ristretto255();
const rng = new SeededPRNG(crypto.getRandomValues(new Uint8Array(32)));
const domainSeparator = new TextEncoder().encode('ACT-v1:example:api:prod');
const params = generateParameters(group, domainSeparator, 64); // L=64 bits
const { privateKey: sk, publicKey: pk } = keyGen(group, rng);

// Issuance: Client requests 100 credits
const ctx = group.hashToScalar(new Uint8Array([1, 2, 3])); // context binding
const [request, clientState] = issueRequest(params, ctx, rng);
const response = issueResponse(params, sk, request, 100n, ctx, rng);
const token = verifyIssuance(params, pk, response, clientState);

// Spending: Client spends 30 credits
const [proof, spendState] = proveSpend(params, token, 30n, rng);
const nullifierDb = new Set<string>();
const refund = verifyAndRefund(params, sk, proof, nullifierDb, 0n, rng);
const newToken = constructRefundToken(params, pk, proof, refund, spendState);
// newToken has 70 credits remaining
```

## Development

| Task    | Command          |
| ------- | ---------------- |
| Install | `npm install`    |
| Build   | `npm run build`  |
| Test    | `npm test`       |
| Lint    | `npm run lint`   |
| Format  | `npm run format` |

### Project Structure

```
packages/
  sigma-proofs/     # Zero-knowledge proof primitives
  act-ts/           # Core ACT protocol
docs/
  ARCHITECTURE.md   # Technical design
  VNEXT_MIGRATION.md # Upcoming spec changes
```

## Status

| Package      | Status                         | Tests       |
| ------------ | ------------------------------ | ----------- |
| sigma-proofs | Complete                       | 112 passing |
| act-ts       | vnext (sigma-draft-compliance) | 124 passing |

### Roadmap

- [x] sigma-proofs: LinearRelation, SchnorrProof, NISigmaProtocol
- [x] sigma-proofs: SHAKE128 Fiat-Shamir (draft-irtf-cfrg-fiat-shamir-01)
- [x] act-ts: Issuance, spending, range proofs (current draft)
- [x] act-ts: vnext with algebraic range proofs (replacing CDS OR-proofs)
- [x] act-ts: TLS wire format encoding (replacing CBOR)
- [x] act-ts: Horner optimization for pow2-weighted sums
- [ ] act-ts: Interop testing with Rust reference implementation

## Security Considerations

This software has not been audited. Please use at your sole discretion. With this in mind, act-ts security relies on the following:

- [Anonymous Credit Tokens](https://datatracker.ietf.org/doc/draft-schlesinger-cfrg-act/) specification by Samuel Schlesinger and Jonathan Katz, based on keyed-verification anonymous credentials and BBS-style signatures
- [Sigma Protocols](https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/) specification for zero-knowledge proofs
- [@noble/curves](https://github.com/paulmillr/noble-curves) for elliptic curve operations (Ristretto255, P-256)
- [@noble/hashes](https://github.com/paulmillr/noble-hashes) for cryptographic hash functions

### Limitations

- **Not quantum-resistant**: Based on discrete logarithm assumptions
- **Draft specifications**: Protocol may change before standardization
- **No constant-time guarantees**: JavaScript runtime limitations (see [@noble/curves documentation](https://github.com/paulmillr/noble-curves#security))

### Reporting Vulnerabilities

If you discover a security vulnerability, please report it via GitHub Security Advisories or contact the maintainers directly. Do not open public issues for security vulnerabilities.

## Related Projects

- [anonymous-credit-tokens](https://github.com/AquilaCrypto/anonymous-credit-tokens) - Rust reference implementation
- [privacypass-ts](https://github.com/cloudflare/privacypass-ts) - Privacy Pass TypeScript library
- [Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html) - RFC 9576 architecture

## License

This project is under the [Apache-2.0](LICENSE) license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache-2.0 licensed as above, without any additional terms or conditions.
