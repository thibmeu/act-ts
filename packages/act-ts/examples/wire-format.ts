// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

/**
 * Example: Wire Format Encoding
 *
 * Demonstrates CBOR serialization for network transmission.
 */

import {
  generateParameters,
  keyGen,
  issueRequest,
  issueResponse,
  verifyIssuance,
  proveSpend,
  encodeIssuanceRequest,
  decodeIssuanceRequest,
  encodeIssuanceResponse,
  decodeIssuanceResponse,
  encodeSpendProof,
  decodeSpendProof,
  encodeCreditToken,
  decodeCreditToken,
  group,
  toHex,
} from '../src/index.js';

export async function wireFormatExample(): Promise<void> {
  console.log('=== ACT Wire Format Example ===\n');

  // Setup
  const params = generateParameters('ACT-v1:example:api:prod:2024-01-15', 8);
  const { privateKey: sk, publicKey: pk } = keyGen();
  const ctx = group.randomScalar();

  // === Issuance Request ===
  console.log('--- Issuance Request ---');
  const [request, clientState] = issueRequest(params);

  const requestBytes = encodeIssuanceRequest(request);
  console.log(`Encoded request: ${requestBytes.length} bytes`);
  console.log(`  Hex: ${toHex(requestBytes).slice(0, 64)}...`);

  const decodedRequest = decodeIssuanceRequest(requestBytes);
  console.log(`  Round-trip: OK`);
  console.log();

  // === Issuance Response ===
  console.log('--- Issuance Response ---');
  const response = issueResponse(params, sk, decodedRequest, 100n, ctx);

  const responseBytes = encodeIssuanceResponse(response);
  console.log(`Encoded response: ${responseBytes.length} bytes`);
  console.log(`  Hex: ${toHex(responseBytes).slice(0, 64)}...`);

  const decodedResponse = decodeIssuanceResponse(responseBytes);
  console.log(`  Round-trip: OK`);
  console.log();

  // === Credit Token (client storage) ===
  console.log('--- Credit Token ---');
  const token = verifyIssuance(params, pk, request, decodedResponse, clientState);

  const tokenBytes = encodeCreditToken(token);
  console.log(`Encoded token: ${tokenBytes.length} bytes`);
  console.log(`  Hex: ${toHex(tokenBytes).slice(0, 64)}...`);

  const decodedToken = decodeCreditToken(tokenBytes);
  console.log(`  Balance: ${decodedToken.c} credits`);
  console.log(`  Round-trip: OK`);
  console.log();

  // === Spend Proof ===
  console.log('--- Spend Proof ---');
  const [proof] = proveSpend(params, decodedToken, 30n);

  const proofBytes = encodeSpendProof(proof);
  console.log(`Encoded proof: ${proofBytes.length} bytes`);
  console.log(`  Hex: ${toHex(proofBytes).slice(0, 64)}...`);

  const decodedProof = decodeSpendProof(proofBytes);
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
