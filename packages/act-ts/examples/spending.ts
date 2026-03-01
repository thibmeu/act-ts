// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

/**
 * Example: Token Spending
 *
 * Demonstrates the spending protocol where a client spends credits
 * from a token and receives a refund token with remaining balance.
 */

import {
  generateParameters,
  keyGen,
  issueRequest,
  issueResponse,
  verifyIssuance,
  proveSpend,
  verifyAndRefund,
  constructRefundToken,
  group,
  toHex,
} from '../src/index.js';

export async function spendingExample(): Promise<void> {
  console.log('=== ACT Spending Example ===\n');

  // Setup (same as issuance)
  const params = generateParameters('ACT-v1:example:api:prod:2024-01-15', 8);
  const { privateKey: sk, publicKey: pk } = keyGen();
  const ctx = group.randomScalar();

  // First, get a token via issuance
  const [request, clientState] = issueRequest(params);
  const response = issueResponse(params, sk, request, 100n, ctx);
  const token = verifyIssuance(params, pk, request, response, clientState);

  console.log(`Starting balance: ${token.c} credits`);
  console.log();

  // Nullifier database (issuer tracks used nullifiers)
  const usedNullifiers = new Set<string>();

  // Client                                       Issuer
  // ====================================================
  //
  // Step 1: Client creates spend proof
  // Proves they have a valid token with sufficient balance
  //
  // Client
  // (proof, spendState) = ProveSpend(params, token, amount)
  const spendAmount = 30n;
  const [proof, spendState] = proveSpend(params, token, spendAmount);
  console.log('Step 1: Client creates spend proof');
  console.log(`  Spending: ${spendAmount} credits`);
  console.log(`  Nullifier revealed: ${toHex(proof.k.toBytes()).slice(0, 32)}...`);
  console.log();

  //
  // The client sends proof to the issuer
  //             proof
  //       ------------------>>
  //
  //                                              Issuer
  // Step 2: Issuer verifies proof and issues refund
  // - Checks nullifier not already used (double-spend prevention)
  // - Verifies the zero-knowledge proof
  // - Records nullifier as used
  // - Issues refund for remaining balance
  //
  // refund = VerifyAndRefund(params, sk, proof, nullifierDb, returnAmount)
  const returnAmount = 0n; // Could return partial credits
  const refund = verifyAndRefund(params, sk, proof, usedNullifiers, returnAmount);
  console.log('Step 2: Issuer verifies and issues refund');
  console.log(`  Proof valid: true`);
  console.log(`  Nullifier recorded (prevents double-spend)`);
  console.log(`  Return amount: ${returnAmount} credits`);
  console.log();

  //
  // The issuer sends refund to the client
  //            refund
  //       <<------------------
  //
  // Client
  // Step 3: Client constructs new token from refund
  //
  // newToken = ConstructRefundToken(params, pk, proof, refund, spendState)
  const newToken = constructRefundToken(params, pk, proof, refund, spendState);
  console.log('Step 3: Client constructs new token');
  console.log(`  New balance: ${newToken.c} credits`);
  console.log(`  New nullifier: ${toHex(newToken.k.toBytes()).slice(0, 32)}...`);
  console.log();

  console.log('Spending complete!');
  console.log(`Spent ${spendAmount} credits, ${newToken.c} credits remaining.\n`);
}

// Run if executed directly
spendingExample().catch(console.error);
