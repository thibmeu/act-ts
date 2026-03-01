// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

/**
 * Example: Token Issuance
 *
 * Demonstrates the issuance protocol where a client requests credits
 * from an issuer and receives a token.
 */

import {
  generateParameters,
  keyGen,
  issueRequest,
  issueResponse,
  verifyIssuance,
  group,
} from '../src/index.js';

export async function issuanceExample(): Promise<void> {
  console.log('=== ACT Issuance Example ===\n');

  // Setup: Generate system parameters and issuer keys
  const domainSeparator = 'ACT-v1:example:api:prod:2024-01-15';
  const L = 8; // 8-bit credits (0-255)
  const params = generateParameters(domainSeparator, L);
  const { privateKey: sk, publicKey: pk } = keyGen();

  console.log(`Domain: ${domainSeparator}`);
  console.log(`Bit length: ${L} (max credits: ${(1n << BigInt(L)) - 1n})`);
  console.log(`Public key: ${Buffer.from(pk.W.toBytes()).toString('hex').slice(0, 32)}...`);
  console.log();

  // Application context (e.g., derived from TokenChallenge)
  const ctx = group.randomScalar();

  // Client                                       Issuer
  // ====================================================
  //
  // Step 1: Client creates blinded request
  // The nullifier k and blinding factor r are kept secret
  //
  // Client
  // (request, state) = IssueRequest(params)
  const [request, clientState] = issueRequest(params);
  console.log('Step 1: Client creates issuance request');
  console.log(
    `  K (commitment): ${Buffer.from(request.K.toBytes()).toString('hex').slice(0, 32)}...`
  );
  console.log();

  //
  // The client sends request to the issuer
  //             request
  //       ------------------>>
  //
  //                                              Issuer
  // Step 2: Issuer verifies request and creates signed response
  // The issuer chooses the credit amount
  //
  // response = IssueResponse(params, sk, request, credits, ctx)
  const credits = 100n;
  const response = issueResponse(params, sk, request, credits, ctx);
  console.log('Step 2: Issuer creates response');
  console.log(`  Credits issued: ${credits}`);
  console.log(
    `  A (signature): ${Buffer.from(response.A.toBytes()).toString('hex').slice(0, 32)}...`
  );
  console.log();

  //
  // The issuer sends response to the client
  //            response
  //       <<------------------
  //
  // Client
  // Step 3: Client verifies response and extracts token
  //
  // token = VerifyIssuance(params, pk, request, response, state)
  const token = verifyIssuance(params, pk, request, response, clientState);
  console.log('Step 3: Client verifies and extracts token');
  console.log(`  Token balance: ${token.c} credits`);
  console.log(`  Nullifier: ${Buffer.from(token.k.toBytes()).toString('hex').slice(0, 32)}...`);
  console.log();

  console.log('Issuance complete!');
  console.log(`Client now has a token with ${token.c} credits.\n`);
}

// Run if executed directly
issuanceExample().catch(console.error);
