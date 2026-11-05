# act-ts

EC-ACT, Anonymous Credit Tokens ([draft-schlesinger-mole-ec-act-00](https://datatracker.ietf.org/doc/draft-schlesinger-mole-ec-act/)), ciphersuite `P256-SHA256`, in TypeScript. Interoperable with [act-rs](https://github.com/Moderation-of-unLinkable-Endorsements/act-rs). See the [repository README](../../README.md) for a quick start, and [`examples/`](./examples) (`npm run examples`) for annotated protocol runs.

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

Protocol functions, key generation included, are `async`; encoders and decoders are synchronous. Amounts are `bigint`. Errors are `ACTError` with the draft's codes (`Deserialize`, `Verify`, `Derive`, `Value`, `Amount`).

`verifySpend` returns a `VerifiedSpend`, the only thing `issueRefund` accepts, so an unverified spend can never be signed. Before refunding, the Moderator must accept the top-up allowance `verified.a` and record `verified.nullifier` atomically, failing if already present. Credentials, Client states, and verified spends are single use within a process. Credential and Client-state consumption is tracked by value, including spread copies and serialization round trips. A digest per consumed value is retained for the module lifetime, so memory grows with successful consumptions; restarting or loading another module instance does not preserve this history. Wallets must still prevent reuse after restoration.

Every randomized function takes an optional `random(n)` source, defaulting to `crypto.getRandomValues`; tests replay the draft's vectors through it.

`createParams(L, { protocolContext })` overrides `ctx_proto`. act-rs at the time of writing still uses the pre-publication `ACTv1-P256-SHA256`; pass `new TextEncoder().encode('ACTv1-P256-SHA256')` to interoperate with it. Everything else is identical.

## Performance

Each operation batches its elliptic-curve multiplications to WebCrypto (ECDH on P-256): native, constant time, and in Node off the main thread. Where WebCrypto is unavailable, the same batches run on [@noble/curves](https://github.com/paulmillr/noble-curves), with identical outputs, several times slower.

Node 26, Intel i7-8650U, against act-rs (`f1bd64b`, as pinned by guac) compiled to wasm and run in the same V8. Ordinary spend (`s > 0`, `a = 0`):

| Operation        | L = 8 | act-rs wasm, L = 8 | L = 64 | act-rs wasm, L = 64 |
| ---------------- | ----: | -----------------: | -----: | ------------------: |
| `issueRequest`   |  2 ms |               1 ms |   2 ms |              0.7 ms |
| `issueResponse`  |  4 ms |               3 ms |   4 ms |                3 ms |
| `finalizeIssue`  |  2 ms |               2 ms |   2 ms |                2 ms |
| `proveSpend`     | 15 ms |              18 ms |  90 ms |               94 ms |
| `verifySpend`    | 11 ms |              19 ms |  69 ms |              114 ms |
| `finalizeRefund` |  2 ms |               2 ms |   2 ms |                2 ms |

Choose the smallest `L` that fits your largest balance.
