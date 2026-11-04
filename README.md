# act-ts: Anonymous Credit Tokens in TypeScript

> **Warning**
> This software is experimental and has not been audited. The underlying cryptographic specifications are IETF drafts subject to change. Use at your own risk.

TypeScript implementation of EC-ACT, Anonymous Credit Tokens: a keyed-verification anonymous credential whose hidden state is a credit balance.

**Specification:** [draft-schlesinger-mole-ec-act-00](https://datatracker.ietf.org/doc/draft-schlesinger-mole-ec-act/), ciphersuite `P256-SHA256`, interoperable with [act-rs](https://github.com/Moderation-of-unLinkable-Endorsements/act-rs).

**Target Environments:** Browser, Cloudflare Workers, Node.js

## Packages

| Package                                 | Description                                                 | Spec                                                                                                                                                                                           |
| --------------------------------------- | ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [sigma-proofs](./packages/sigma-proofs) | Sigma protocols for linear relations, compact and batchable | [draft-irtf-cfrg-sigma-protocols-03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/03/), [fiat-shamir-03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/03/) |
| [act-ts](./packages/act-ts)             | EC-ACT credential scheme                                    | [draft-schlesinger-mole-ec-act-00](https://datatracker.ietf.org/doc/draft-schlesinger-mole-ec-act/)                                                                                            |

EC-ACTv1 pins revision -03 of the Sigma and Fiat-Shamir drafts (Section 5); -04 changes the relation serialization and would need a new ciphersuite identifier.

## What is ACT?

A Moderator issues a Credential with a hidden balance. The Client later spends a public amount `s`, proving in zero knowledge that the balance covers it, and receives a refund for the remainder plus a Moderator-chosen return amount `t <= s + a`, where `a` is a top-up allowance declared by the spend. The Moderator never learns the balance, and cannot link a spend to the issuance or refund that produced the Credential, nor two spends to each other. A nullifier revealed by each spend prevents double spending.

## Quick Example

```typescript
import {
  createParams,
  generateKeys,
  issueRequest,
  issueResponse,
  finalizeIssue,
  proveSpend,
  verifySpend,
  issueRefund,
  finalizeRefund,
  encodeSpend,
  decodeSpend,
} from 'act-ts';

const params = createParams(8); // balances below 2^8
const { skM, pkM } = generateKeys(params); // Moderator; pkM is published
const ctxCred = new TextEncoder().encode('epoch-42'); // agreed out of band

// Issuance
const { state, request } = issueRequest(params);
const response = issueResponse(params, skM, ctxCred, 100n, request);
const credential = finalizeIssue(params, pkM, ctxCred, state, response);

// Spend 30 credits, no top-up, bound to the Moderator's challenge.
const ctxSpend = new TextEncoder().encode('challenge-digest');
const spend = proveSpend(params, credential, ctxCred, 30n, 0n, ctxSpend);
const wire = encodeSpend(spend.proof); // store spend.state durably first

// Moderator: verify, then record verified.nullifier atomically before refunding.
const verified = verifySpend(params, skM, ctxCred, ctxSpend, decodeSpend(params, wire));
const refund = issueRefund(verified, 5n);

const next = finalizeRefund(params, pkM, ctxCred, spend.state, refund);
console.log(next.c); // 75n
```

## Development

```bash
npm install       # Install dependencies
npm run build     # Build all packages
npm test          # Run tests
npm run lint      # Lint and format check
npm run bench     # Benchmarks
```

Conformance: act-ts replays the draft's Appendix A and every act-rs vector file (L = 1, 2, 4, 8, 16, 64) byte for byte; sigma-proofs passes all 75 vectors of sigma-protocols-03 Appendix A, including adversarial ones, and reproduces every valid proof byte for byte.

## Security Considerations

This software has not been audited. Please use at your sole discretion. act-ts security relies on:

- [EC-ACT](https://datatracker.ietf.org/doc/draft-schlesinger-mole-ec-act/) and [EC-IHAT](https://datatracker.ietf.org/doc/draft-ladd-mole-ec-ihat/) (group and derivation functions)
- [Sigma Protocols](https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/) and [Fiat-Shamir](https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/)
- [@noble/curves](https://github.com/paulmillr/noble-curves) for P-256 and hash-to-curve, [@noble/hashes](https://github.com/paulmillr/noble-hashes) for SHA-256 and SHAKE128

The deployment remains responsible for the nullifier store (record each nullifier atomically, failing if present, before releasing a refund), for storing the Client's spend state durably before the spend leaves the Client, and for a coarse credential context (Section 6 of the draft). Within a process, act-ts refuses to reuse a Credential, a Client state, or a verified spend.

### Limitations

- **Not quantum-resistant**: based on discrete logarithm assumptions
- **Draft specifications**: the protocol may change before standardization
- **No constant-time guarantees**: JavaScript BigInt is not constant time (see [@noble/curves](https://github.com/paulmillr/noble-curves#security)); secret-dependent branches are avoided on a best-effort basis
- **No secret zeroization**: JavaScript cannot reliably wipe BigInt values

## Related Projects

- [act-rs](https://github.com/Moderation-of-unLinkable-Endorsements/act-rs) - Rust implementation
- [MOLE drafts](https://github.com/Moderation-of-unLinkable-Endorsements/internet-drafts)

## License

This project is under the [Apache-2.0](LICENSE) license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache-2.0 licensed as above, without any additional terms or conditions.
