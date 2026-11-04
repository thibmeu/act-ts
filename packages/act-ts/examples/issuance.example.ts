// Example: Credential issuance (draft-schlesinger-mole-ec-act-00, Section 4.5)
//
// A Moderator issues a Credential holding 100 credits. The Client learns the
// balance; the Moderator never sees the nullifier k or blinding factor r it
// signs, so it cannot recognize the Credential when it is later spent.

import {
  createParams,
  decodeIssueRequest,
  decodeIssueResponse,
  decodePublicKey,
  encodeIssueRequest,
  encodeIssueResponse,
  encodePublicKey,
  finalizeIssue,
  generateKeys,
  issueRequest,
  issueResponse,
} from '../src/index.ts';

export async function issuance(): Promise<boolean> {
  // Configuration (Section 4.1)
  //
  // [ Moderator ] picks the balance width L and a key pair, and publishes L and pkM
  // [ Everybody ] agrees on a coarse credential context, e.g. the current epoch
  const params = createParams(8); // balances in [0, 2^8)
  const { skM, pkM } = await generateKeys(params);
  const ctxCred = new TextEncoder().encode('example.com/credits/2026-11');

  // [ Client ] fetches the Moderator's configuration
  const moderatorKey = decodePublicKey(encodePublicKey(pkM));

  // Issuance (Figure 1)
  //
  //   Client(pkM, ctx_cred)                     Moderator(skM, ctx_cred)
  //   ----------------------------------------------------------------
  //   state, request = IssueRequest()

  // [ Client ] commits to a fresh nullifier k and blinding factor r, and proves
  // it knows the opening. `state` stays on the Client.
  const { state, request } = await issueRequest(params);

  //                               request
  //                              -------->            (129 bytes)
  const requestBytes = encodeIssueRequest(request);

  //                       response = IssueResponse(skM, ctx_cred, c, request)

  // [ Moderator ] verifies the proof, chooses the balance c, and signs
  // B + c * H1 + ctx * H4 + K without learning k or r
  const response = await issueResponse(
    params,
    skM,
    ctxCred,
    100n,
    decodeIssueRequest(requestBytes)
  );

  //                               response
  //                              <--------            (137 bytes)
  const responseBytes = encodeIssueResponse(response);

  //   credential = FinalizeIssue(pkM, ctx_cred, state, response)

  // [ Client ] checks the Moderator's proof of correct signing and assembles
  // the Credential (k, c, r, A, e). It is stored, never sent.
  const credential = await finalizeIssue(
    params,
    moderatorKey,
    ctxCred,
    state,
    decodeIssueResponse(params, responseBytes)
  );

  console.log(
    `  issued ${credential.c} credits (request ${requestBytes.length} B, response ${responseBytes.length} B)`
  );
  return credential.c === 100n;
}
