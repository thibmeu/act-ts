// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

/**
 * Example: Full ACT Flow
 *
 * Demonstrates a complete session: issuance, multiple spends,
 * and double-spend prevention.
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
  ACTError,
  type CreditToken,
} from '../src/index.js';

export async function fullFlowExample(): Promise<void> {
  console.log('=== ACT Full Flow Example ===\n');

  // Setup
  const params = generateParameters('ACT-v1:example:api:prod:2024-01-15', 8);
  const { privateKey: sk, publicKey: pk } = keyGen();
  const ctx = group.randomScalar();
  const usedNullifiers = new Set<string>();

  // === Phase 1: Issuance ===
  console.log('--- Phase 1: Issuance ---');
  const [request, clientState] = issueRequest(params);
  const response = issueResponse(params, sk, request, 100n, ctx);
  let token: CreditToken = verifyIssuance(params, pk, request, response, clientState);
  console.log(`Issued token with ${token.c} credits\n`);

  // === Phase 2: Multiple Spends ===
  console.log('--- Phase 2: Multiple Spends ---');

  const spendAmounts = [25n, 30n, 20n];
  for (const amount of spendAmounts) {
    console.log(`Spending ${amount} credits (balance: ${token.c})...`);

    const [proof, spendState] = proveSpend(params, token, amount);
    const refund = verifyAndRefund(params, sk, proof, usedNullifiers, 0n);
    token = constructRefundToken(params, pk, proof, refund, spendState);

    console.log(`  New balance: ${token.c} credits`);
  }
  console.log();

  // === Phase 3: Double-Spend Prevention ===
  console.log('--- Phase 3: Double-Spend Prevention ---');

  // Save the current token's nullifier
  const savedNullifier = Buffer.from(token.k.toBytes()).toString('hex');

  // Spend normally
  const [proof1, spendState1] = proveSpend(params, token, 10n);
  const refund1 = verifyAndRefund(params, sk, proof1, usedNullifiers, 0n);
  const newToken = constructRefundToken(params, pk, proof1, refund1, spendState1);
  console.log(`First spend: 10 credits (balance now: ${newToken.c})`);

  // Try to double-spend with the old token
  console.log('Attempting double-spend with old token...');
  const [proof2] = proveSpend(params, token, 5n); // Using OLD token
  try {
    verifyAndRefund(params, sk, proof2, usedNullifiers, 0n);
    console.log('  ERROR: Double-spend should have been rejected!');
  } catch (e) {
    if (e instanceof ACTError) {
      console.log(`  Rejected: ${e.message}`);
    } else {
      throw e;
    }
  }
  console.log();

  // === Phase 4: Spend Remaining Balance ===
  console.log('--- Phase 4: Spend Remaining Balance ---');
  token = newToken;

  // Spend everything
  const finalAmount = token.c;
  const [finalProof, finalState] = proveSpend(params, token, finalAmount);
  const finalRefund = verifyAndRefund(params, sk, finalProof, usedNullifiers, 0n);
  const emptyToken = constructRefundToken(params, pk, finalProof, finalRefund, finalState);

  console.log(`Spent remaining ${finalAmount} credits`);
  console.log(`Final balance: ${emptyToken.c} credits`);
  console.log();

  // === Summary ===
  console.log('--- Summary ---');
  console.log(`Total issued: 100 credits`);
  console.log(`Total spent: ${25n + 30n + 20n + 10n + finalAmount} credits`);
  console.log(`Nullifiers recorded: ${usedNullifiers.size}`);
  console.log(`Double-spend attempts blocked: 1`);
  console.log('\nFull flow complete!');
}

// Run if executed directly
fullFlowExample().catch(console.error);
