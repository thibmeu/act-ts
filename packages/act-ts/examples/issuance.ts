// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

/**
 * Example: Token Issuance
 *
 * Demonstrates the issuance protocol where a client requests credits
 * from an issuer and receives a token.
 */

import {
  ristretto255,
  generateParameters,
  keyGen,
  issueRequest,
  issueResponse,
  verifyIssuance,
  WebCryptoPRNG,
  toHex,
} from '../src/index.js';

export async function issuanceExample(): Promise<void> {
  console.log('=== ACT Issuance Example ===\n');

  // Setup: Generate system parameters and issuer keys
  const group = ristretto255;
  const rng = new WebCryptoPRNG();
  const domainSeparator = new TextEncoder().encode('ACT-v1:example:api:prod');
  const L = 8; // 8-bit credits (0-255)
  const params = generateParameters(group, domainSeparator, L);
  const { privateKey: sk, publicKey: pk } = keyGen(group, rng);

  console.log(`Domain: ${new TextDecoder().decode(domainSeparator)}`);
  console.log(`Bit length: ${L} (max credits: ${(1n << BigInt(L)) - 1n})`);
  console.log(`Public key: ${toHex(pk.W.toBytes()).slice(0, 32)}...`);
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
  // (request, state) = IssueRequest(params, ctx)
  const [request, clientState] = issueRequest(params, ctx, rng);
  console.log('Step 1: Client creates issuance request');
  console.log(`  K (commitment): ${toHex(request.K.toBytes()).slice(0, 32)}...`);
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
  const response = issueResponse(params, sk, request, credits, ctx, rng);
  console.log('Step 2: Issuer creates response');
  console.log(`  Credits issued: ${credits}`);
  console.log(`  A (signature): ${toHex(response.A.toBytes()).slice(0, 32)}...`);
  console.log();

  //
  // The issuer sends response to the client
  //            response
  //       <<------------------
  //
  // Client
  // Step 3: Client verifies response and extracts token
  //
  // token = VerifyIssuance(params, pk, response, state)
  const token = verifyIssuance(params, pk, response, clientState);
  console.log('Step 3: Client verifies and extracts token');
  console.log(`  Token balance: ${token.c} credits`);
  console.log(`  Nullifier: ${toHex(token.k.toBytes()).slice(0, 32)}...`);
  console.log();

  console.log('Issuance complete!');
  console.log(`Client now has a token with ${token.c} credits.\n`);
}

// Run if executed directly
issuanceExample().catch(console.error);
