// Example: Spending and refund (draft-schlesinger-mole-ec-act-00, Section 4.6)
//
// The Client spends 30 of its 100 credits. The Moderator verifies the spend
// without learning the balance, records the nullifier to prevent a second
// spend, and refunds the remainder plus 5 credits it chooses to return.

import {
  type Credential,
  createParams,
  decodeRefund,
  decodeSpend,
  encodeRefund,
  encodeSpend,
  encodeSpendState,
  finalizeIssue,
  finalizeRefund,
  generateKeys,
  issueRefund,
  issueRequest,
  issueResponse,
  type Params,
  type Point,
  proveSpend,
  verifySpend,
} from '../src/index.ts';

const hex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

async function issue(
  params: Params,
  skM: bigint,
  pkM: Point,
  ctxCred: Uint8Array,
  c: bigint
): Promise<Credential> {
  const { state, request } = await issueRequest(params);
  const response = await issueResponse(params, skM, ctxCred, c, request);
  return finalizeIssue(params, pkM, ctxCred, state, response);
}

export async function spending(): Promise<boolean> {
  const params = createParams(8);
  const { skM, pkM } = await generateKeys(params);
  const ctxCred = new TextEncoder().encode('example.com/credits/2026-11');
  const credential = await issue(params, skM, pkM, ctxCred, 100n);

  // [ Moderator ] keeps a permanent nullifier store (Section 6, "Nullifier store")
  const nullifiers = new Set<string>();

  // Spending inputs at both parties: s, a, ctx_spend
  //
  // [ Moderator ] challenges the Client for s = 30 credits with no top-up (a = 0),
  // and binds the spend to its challenge, e.g. a SHA-256 digest of it
  const [s, a] = [30n, 0n];
  const ctxSpend = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode('POST /api/generate #8271'))
  );

  //   Client(pkM, ctx_cred)                     Moderator(skM, ctx_cred)
  //   ----------------------------------------------------------------
  //   state, proof = ProveSpend(credential, ctx_cred, s, a, ctx_spend)

  // [ Client ] rerandomizes its signature, commits to the next nullifier and to
  // the remainder bit by bit, and proves 0 <= c - s and c + a < 2^L. This
  // consumes the Credential.
  const { state, proof } = await proveSpend(params, credential, ctxCred, s, a, ctxSpend);

  // [ Client ] MUST store `state` durably before the proof leaves the device:
  // without it the refund is unusable and the credits are lost.
  const storedState = encodeSpendState(state);

  //                         proof (includes nullifier k)
  //                              -------->
  const spendBytes = encodeSpend(proof);

  //                        VerifySpend(skM, ctx_cred, ctx_spend, proof)
  //                        refund = IssueRefund(skM, ctx_cred, proof, t)
  //                        Record proof.k atomically, failing if present

  // [ Moderator ] verifies the proof under its key and both contexts. Amounts
  // are checked against 2^L before the proof (Section 4.3).
  const verified = await verifySpend(
    params,
    skM,
    ctxCred,
    ctxSpend,
    decodeSpend(params, spendBytes)
  );

  // [ Moderator ] grants the allowance and records the nullifier. In production
  // this check-and-insert is one atomic operation in durable storage.
  const nullifier = hex(verified.nullifier);
  if (verified.a !== 0n || nullifiers.has(nullifier)) return false;
  nullifiers.add(nullifier);

  // [ Moderator ] serves the request, then refunds c - s + t for t <= s + a,
  // without learning c
  const refund = await issueRefund(verified, 5n);

  //                                refund
  //                              <--------
  const refundBytes = encodeRefund(refund);

  //   credential = FinalizeRefund(pkM, ctx_cred, state, refund)

  // [ Client ] checks the signature on its new commitment and assembles the next
  // Credential, with a fresh nullifier and balance 100 - 30 + 5
  const next = await finalizeRefund(params, pkM, ctxCred, state, decodeRefund(params, refundBytes));

  console.log(
    `  spent ${s}, returned ${refund.t}: balance ${next.c} (spend ${spendBytes.length} B, state ${storedState.length} B)`
  );
  return next.c === 75n;
}
