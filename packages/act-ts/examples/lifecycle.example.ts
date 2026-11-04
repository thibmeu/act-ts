// Example: Credential lifecycle (draft-schlesinger-mole-ec-act-00, Sections 4.6 and 6)
//
// One Credential through every spend shape, then what the Moderator must
// catch: a replayed spend, a Credential from an expired context, and a
// Client asking again for a refund it never received.

import {
  ACTError,
  type Credential,
  createParams,
  decodeSpend,
  encodeSpend,
  finalizeIssue,
  finalizeRefund,
  generateKeys,
  issueRefund,
  issueRequest,
  issueResponse,
  proveSpend,
  type RefundMessage,
  type SpendMessage,
  verifySpend,
} from '../src/index.ts';

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const hex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

export async function lifecycle(): Promise<boolean> {
  const params = createParams(8);
  const { skM, pkM } = await generateKeys(params);
  const epoch = enc('example.com/credits/2026-11');
  const ctxSpend = enc('challenge-digest');

  // [ Moderator ] keeps the nullifier store, and the refund issued for each
  // nullifier so a Client that lost it can ask again (Section 4.6.5)
  const refunds = new Map<string, RefundMessage>();

  // [ Moderator ] VerifySpend, then record the nullifier atomically, then IssueRefund
  async function moderate(
    spend: SpendMessage,
    ctxCred: Uint8Array,
    t: bigint
  ): Promise<RefundMessage> {
    const verified = await verifySpend(
      params,
      skM,
      ctxCred,
      ctxSpend,
      decodeSpend(params, encodeSpend(spend))
    );
    const nullifier = hex(verified.nullifier);
    if (refunds.has(nullifier)) throw new Error('double spend');
    const refund = await issueRefund(verified, t);
    refunds.set(nullifier, refund);
    return refund;
  }

  // [ Client ] spends s with top-up allowance a; the Moderator returns t <= s + a
  async function spend(
    credential: Credential,
    s: bigint,
    a: bigint,
    t: bigint
  ): Promise<Credential> {
    const { state, proof } = await proveSpend(params, credential, epoch, s, a, ctxSpend);
    return finalizeRefund(params, pkM, epoch, state, await moderate(proof, epoch, t));
  }

  const { state, request } = await issueRequest(params);
  let credential = await finalizeIssue(
    params,
    pkM,
    epoch,
    state,
    await issueResponse(params, skM, epoch, 40n, request)
  );

  // The four spend shapes (Section 4.6.1); only s, a and t are public.
  //
  //   s > 0, a = 0   ordinary spend          balance c - s + t, t <= s
  //   s = 0, a = 0   refresh                 balance c, new nullifier
  //   s = 0, a > 0   pure top-up             balance c + t, t <= a
  //   s > 0, a > 0   spend with top-up       balance c - s + t, t <= s + a
  credential = await spend(credential, 10n, 0n, 0n); // 40 -> 30
  credential = await spend(credential, 0n, 0n, 0n); //  30 -> 30
  credential = await spend(credential, 0n, 50n, 50n); // 30 -> 80
  credential = await spend(credential, 20n, 10n, 25n); // 80 -> 85
  const shapesOk = credential.c === 85n;

  // Double spend
  //
  //   Client                                    Moderator
  //   proof = ProveSpend(credential, ...)
  //                               proof
  //                              -------->      refund, k recorded
  //                               proof (again)
  //                              -------->      the proof still verifies,
  //                                             but k is recorded: rejected
  //
  // act-ts already refuses to prove twice from one Credential in a process;
  // a replayed message (or a restored backup) is caught by the store.
  const { state: spendState, proof } = await proveSpend(
    params,
    credential,
    epoch,
    5n,
    0n,
    ctxSpend
  );
  await moderate(proof, epoch, 0n); // its refund is lost in transit, below
  const replayRejected = await moderate(proof, epoch, 0n).then(
    () => false,
    (e: unknown) => e instanceof Error && e.message === 'double spend'
  );

  // Refund recovery
  //
  //   Client                                    Moderator
  //                               proof
  //                              -------->      refund, k recorded
  //                               refund
  //                              <---X---       lost in transit
  //                    "refund for nullifier k?"
  //                              -------->      looks up k
  //                               refund
  //                              <--------
  //   credential = FinalizeRefund(state, refund)
  //
  // The Client kept `state` (and the proof) durably, so it can finish later.
  // The nullifier k is the first field of the spend message (Section 4.7).
  const resent = refunds.get(hex(encodeSpend(proof).subarray(0, 32)));
  if (!resent) return false;
  credential = await finalizeRefund(params, pkM, epoch, spendState, resent);
  const recovered = credential.c === 80n;

  // Context expiry: the Moderator moves to a new epoch without rotating its
  // key. A Credential issued under the old context no longer verifies.
  const { proof: stale } = await proveSpend(params, credential, epoch, 1n, 0n, ctxSpend);
  const expired = await moderate(stale, enc('example.com/credits/2026-12'), 0n).then(
    () => false,
    (e: unknown) => e instanceof ACTError && e.code === 'Verify'
  );

  console.log(
    `  shapes ${shapesOk ? 'ok' : 'FAIL'}, replay rejected ${replayRejected}, refund recovered ${recovered}, old epoch rejected ${expired}`
  );
  return shapesOk && replayRejected && recovered && expired;
}
