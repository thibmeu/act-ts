// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

/**
 * Example: Full ACT Flow
 *
 * Demonstrates a complete session: issuance, multiple spends,
 * and double-spend prevention.
 */

import {
  ristretto255,
  generateParameters,
  keyGen,
  issueRequest,
  issueResponse,
  verifyIssuance,
  proveSpend,
  verifyAndRefund,
  constructRefundToken,
  ACTError,
  WebCryptoPRNG,
  toHex,
  type CreditToken,
} from '../src/index-vnext.js';

export async function fullFlowExample(): Promise<void> {
  console.log('=== ACT Full Flow Example ===\n');

  // Setup
  const group = ristretto255;
  const rng = new WebCryptoPRNG();
  const domainSeparator = new TextEncoder().encode('ACT-v1:example:api:prod');
  const params = generateParameters(group, domainSeparator, 8);
  const { privateKey: sk, publicKey: pk } = keyGen(group, rng);
  const ctx = group.randomScalar();
  const usedNullifiers = new Set<string>();

  // === Phase 1: Issuance ===
  console.log('--- Phase 1: Issuance ---');
  const [request, clientState] = issueRequest(params, ctx, rng);
  const response = issueResponse(params, sk, request, 100n, ctx, rng);
  let token: CreditToken = verifyIssuance(params, pk, response, clientState);
  console.log(`Issued token with ${token.c} credits\n`);

  // === Phase 2: Multiple Spends ===
  console.log('--- Phase 2: Multiple Spends ---');

  const spendAmounts = [25n, 30n, 20n];
  for (const amount of spendAmounts) {
    console.log(`Spending ${amount} credits (balance: ${token.c})...`);

    const [proof, spendState] = proveSpend(params, token, amount, rng);
    const refund = verifyAndRefund(params, sk, proof, usedNullifiers, 0n, rng);
    token = constructRefundToken(params, pk, proof, refund, spendState);

    console.log(`  New balance: ${token.c} credits`);
  }
  console.log();

  // === Phase 3: Double-Spend Prevention ===
  console.log('--- Phase 3: Double-Spend Prevention ---');

  // Save the current token's nullifier
  const _savedNullifier = toHex(token.k.toBytes());

  // Spend normally
  const [proof1, spendState1] = proveSpend(params, token, 10n, rng);
  const refund1 = verifyAndRefund(params, sk, proof1, usedNullifiers, 0n, rng);
  const newToken = constructRefundToken(params, pk, proof1, refund1, spendState1);
  console.log(`First spend: 10 credits (balance now: ${newToken.c})`);

  // Try to double-spend with the old token
  console.log('Attempting double-spend with old token...');
  const [proof2] = proveSpend(params, token, 5n, rng); // Using OLD token
  try {
    verifyAndRefund(params, sk, proof2, usedNullifiers, 0n, rng);
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
  const [finalProof, finalState] = proveSpend(params, token, finalAmount, rng);
  const finalRefund = verifyAndRefund(params, sk, finalProof, usedNullifiers, 0n, rng);
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
