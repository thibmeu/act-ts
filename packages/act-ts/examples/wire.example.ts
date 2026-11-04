// Example: Wire and storage encodings (draft-schlesinger-mole-ec-act-00, Section 4.7)
//
// What crosses the network, what the Client must store, and how big each is.
// Elements are 33 bytes (compressed P-256), scalars 32, amounts 8 (uint64).

import {
  createParams,
  decodeCredential,
  decodeSpend,
  decodeSpendState,
  encodeCredential,
  encodeIssueRequest,
  encodeIssueResponse,
  encodeRefund,
  encodeSpend,
  encodeSpendState,
  finalizeIssue,
  finalizeRefund,
  generateKeys,
  issueRefund,
  issueRequest,
  issueResponse,
  proveSpend,
  rangeWeights,
  verifySpend,
} from '../src/index.ts';

export async function wire(): Promise<boolean> {
  const L = 8;
  const params = createParams(L);
  const { skM, pkM } = await generateKeys(params);
  const ctxCred = new TextEncoder().encode('example.com/credits/2026-11');
  const ctxSpend = new TextEncoder().encode('challenge-digest');

  const { state, request } = await issueRequest(params);
  const response = await issueResponse(params, skM, ctxCred, 200n, request);
  const credential = await finalizeIssue(params, pkM, ctxCred, state, response);

  //   struct {                        struct {
  //     Element K;                      Element A;
  //     opaque pok[3 * Ns];             Scalar e;
  //   } IssueRequestMessage;  129 B     uint64 c;
  //                                     opaque pok[2 * Ns];
  //                                   } IssueResponseMessage;  137 B
  const sizes = [encodeIssueRequest(request).length, encodeIssueResponse(response).length];

  // [ Client ] stores the Credential (k, c, r, A, e): 137 B of secrets.
  // Encrypt it at rest; restoring a spent Credential from a backup only
  // yields a double spend the Moderator rejects.
  const stored = encodeCredential(credential);
  const restored = decodeCredential(params, stored);

  //   struct {
  //     Scalar k;  uint64 s;  uint64 a;
  //     Element A_prime;  Element B_bar;  Element K_n;
  //     select (s + a) {
  //       case 0:  Element Com_c;              refresh: 468 B
  //       default: Element Com1[n];            129 n + 403 B
  //     };
  //     opaque pok[(Nw + 1) * Ns];             Nw = 7 + 3 n, or 8
  //   } SpendMessage;
  //
  // n = len(RangeWeights(2^L - 1 - (s + a))) is public: it is L unless
  // s + a >= 2^(L-1), so a Moderator should keep challenges small.
  const spend = await proveSpend(params, restored, ctxCred, 150n, 0n, ctxSpend);
  const spendBytes = encodeSpend(spend.proof);
  const n = rangeWeights(params, (1n << BigInt(L)) - 1n - 150n).length;

  // [ Client ] stores the spend state before sending: 121 B.
  //   kstar || r_star || uint64 v1 || uint64 s || uint64 a || K_prime
  const stateBytes = encodeSpendState(spend.state);

  const verified = await verifySpend(
    params,
    skM,
    ctxCred,
    ctxSpend,
    decodeSpend(params, spendBytes)
  );
  const refund = await issueRefund(verified, 0n);
  const next = await finalizeRefund(
    params,
    pkM,
    ctxCred,
    decodeSpendState(params, stateBytes),
    refund
  );

  console.log(
    `  request ${sizes[0]} B, response ${sizes[1]} B, credential ${stored.length} B, ` +
      `spend ${spendBytes.length} B (n = ${n}), spend state ${stateBytes.length} B, refund ${encodeRefund(refund).length} B`
  );
  return (
    sizes[0] === 129 &&
    sizes[1] === 137 &&
    stored.length === 137 &&
    spendBytes.length === 129 * n + 403 &&
    stateBytes.length === 121 &&
    next.c === 50n
  );
}
