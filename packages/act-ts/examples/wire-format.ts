// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

/**
 * Example: Wire Format Encoding
 *
 * Demonstrates TLS presentation language serialization for network transmission.
 */

import {
  ristretto255,
  generateParameters,
  keyGen,
  issueRequest,
  issueResponse,
  verifyIssuance,
  proveSpend,
  IssuanceRequest,
  IssuanceResponse,
  SpendProof,
  CreditToken,
  WebCryptoPRNG,
  toHex,
} from '../src/index.js';

export async function wireFormatExample(): Promise<void> {
  console.log('=== ACT Wire Format Example ===\n');

  // Setup
  const group = ristretto255;
  const rng = new WebCryptoPRNG();
  const domainSeparator = new TextEncoder().encode('ACT-v1:example:api:prod');
  const params = generateParameters(group, domainSeparator, 8);
  const { privateKey: sk, publicKey: pk } = keyGen(group, rng);
  const ctx = group.randomScalar();

  // === Issuance Request ===
  console.log('--- Issuance Request ---');
  const [request, clientState] = issueRequest(params, ctx, rng);

  const requestBytes = IssuanceRequest.serialize(request);
  console.log(`Encoded request: ${requestBytes.length} bytes`);
  console.log(`  Hex: ${toHex(requestBytes).slice(0, 64)}...`);

  const decodedRequest = IssuanceRequest.deserialize(group, requestBytes);
  console.log(`  Round-trip: OK`);
  console.log();

  // === Issuance Response ===
  console.log('--- Issuance Response ---');
  const response = issueResponse(params, sk, decodedRequest, 100n, ctx, rng);

  const responseBytes = IssuanceResponse.serialize(group, { ...response, ctx });
  console.log(`Encoded response: ${responseBytes.length} bytes`);
  console.log(`  Hex: ${toHex(responseBytes).slice(0, 64)}...`);

  const decodedResponse = IssuanceResponse.deserialize(group, responseBytes);
  console.log(`  Round-trip: OK`);
  console.log();

  // === Credit Token (client storage) ===
  console.log('--- Credit Token ---');
  const token = verifyIssuance(params, pk, decodedResponse, clientState);

  const tokenBytes = CreditToken.serialize(group, token);
  console.log(`Encoded token: ${tokenBytes.length} bytes`);
  console.log(`  Hex: ${toHex(tokenBytes).slice(0, 64)}...`);

  const decodedToken = CreditToken.deserialize(group, tokenBytes);
  console.log(`  Balance: ${decodedToken.c} credits`);
  console.log(`  Round-trip: OK`);
  console.log();

  // === Spend Proof ===
  console.log('--- Spend Proof ---');
  const [proof] = proveSpend(params, decodedToken, 30n, rng);

  const proofBytes = SpendProof.serialize(group, proof);
  console.log(`Encoded proof: ${proofBytes.length} bytes`);
  console.log(`  Hex: ${toHex(proofBytes).slice(0, 64)}...`);

  const decodedProof = SpendProof.deserialize(group, params.L, proofBytes);
  console.log(`  Spend amount: ${decodedProof.s}`);
  console.log(`  Round-trip: OK`);
  console.log();

  // === Size Summary ===
  console.log('--- Size Summary ---');
  console.log(`  Issuance request:  ${requestBytes.length} bytes`);
  console.log(`  Issuance response: ${responseBytes.length} bytes`);
  console.log(`  Credit token:      ${tokenBytes.length} bytes`);
  console.log(`  Spend proof:       ${proofBytes.length} bytes`);
  console.log('\nWire format example complete!');
}

// Run if executed directly
wireFormatExample().catch(console.error);
