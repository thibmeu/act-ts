# act-ts

EC-ACT, Anonymous Credit Tokens ([draft-schlesinger-mole-ec-act-00](https://datatracker.ietf.org/doc/draft-schlesinger-mole-ec-act/)), ciphersuite `P256-SHA256`, in TypeScript. Interoperable with [act-rs](https://github.com/Moderation-of-unLinkable-Endorsements/act-rs). See the [repository README](../../README.md) for an end-to-end example.

## API

| Draft (Section)        | Function                                                  | Run by    |
| ---------------------- | --------------------------------------------------------- | --------- |
| Configuration (4.1)    | `createParams(L)`                                         | both      |
| Key generation (3.4)   | `generateKeys(params)`, `deriveKeys(params, seed, info)`  | Moderator |
| IssueRequest (4.5.2)   | `issueRequest(params)`                                    | Client    |
| IssueResponse (4.5.3)  | `issueResponse(params, skM, ctxCred, c, request)`         | Moderator |
| FinalizeIssue (4.5.4)  | `finalizeIssue(params, pkM, ctxCred, state, response)`    | Client    |
| ProveSpend (4.6.2)     | `proveSpend(params, credential, ctxCred, s, a, ctxSpend)` | Client    |
| VerifySpend (4.6.3)    | `verifySpend(params, skM, ctxCred, ctxSpend, proof)`      | Moderator |
| IssueRefund (4.6.4)    | `issueRefund(verified, t)`                                | Moderator |
| FinalizeRefund (4.6.5) | `finalizeRefund(params, pkM, ctxCred, state, refund)`     | Client    |
| Encodings (4.7)        | `encode*` / `decode*` for every message, state, and key   |           |

Each protocol function has an `…Async` twin (`proveSpendAsync`, `verifySpendAsync`, …) returning a promise of the same result, several times faster; see Performance. Amounts are `bigint`. Errors are `ACTError` with the draft's codes (`Deserialize`, `Verify`, `Derive`, `Value`, `Amount`).

`verifySpend` returns a `VerifiedSpend`, the only thing `issueRefund` accepts, so an unverified spend can never be signed. Before refunding, the Moderator must accept the top-up allowance `verified.a` and record `verified.nullifier` atomically, failing if already present. Credentials, Client states, and verified spends are single use within a process.

Every randomized function takes an optional `random(n)` source, defaulting to `crypto.getRandomValues`; tests replay the draft's vectors through it.

`createParams(L, { protocolContext })` overrides `ctx_proto`. act-rs at the time of writing still uses the pre-publication `ACTv1-P256-SHA256`; pass `new TextEncoder().encode('ACTv1-P256-SHA256')` to interoperate with it. Everything else is identical.

## Performance

Every operation has a synchronous form, on [@noble/curves](https://github.com/paulmillr/noble-curves), and an `…Async` form that batches the elliptic-curve multiplications to WebCrypto (ECDH on P-256): native, constant time, and in Node off the main thread. Outputs are identical. Engines without the needed WebCrypto support fall back to noble.

Node 26, Intel i7-8650U, against act-rs (`f1bd64b`, as pinned by guac) compiled to wasm and run in the same V8. Ordinary spend (`s > 0`, `a = 0`):

| Operation        | sync, L = 8 | async, L = 8 | act-rs wasm, L = 8 | async, L = 64 | act-rs wasm, L = 64 |
| ---------------- | ----------: | -----------: | -----------------: | ------------: | ------------------: |
| `issueRequest`   |        2 ms |         2 ms |               1 ms |          2 ms |              0.7 ms |
| `issueResponse`  |       13 ms |         4 ms |               3 ms |          4 ms |                3 ms |
| `finalizeIssue`  |        9 ms |         2 ms |               2 ms |          2 ms |                2 ms |
| `proveSpend`     |       45 ms |        15 ms |              18 ms |         84 ms |               94 ms |
| `verifySpend`    |       73 ms |        11 ms |              19 ms |         75 ms |              114 ms |
| `finalizeRefund` |        9 ms |         2 ms |               2 ms |          2 ms |                2 ms |

Choose the smallest `L` that fits your largest balance.
