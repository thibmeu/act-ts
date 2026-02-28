/**
 * Non-Interactive Schnorr Proof Example
 *
 * Proves knowledge of a discrete logarithm using Fiat-Shamir:
 *   PoK{(x): X = x*G}
 *
 * This is the primary use case for real applications (HTTP APIs, etc.)
 *
 * Run: npx tsx examples/ni-schnorr.ts
 */

import { LinearRelation, NISigmaProtocol, ristretto255 } from '../src/index.js';

const group = ristretto255;

// === Setup ===
const G = group.generator();
const x = group.randomScalar(); // Prover's secret
const X = G.multiply(x); // Public value

console.log('=== Non-Interactive Schnorr Proof ===\n');

// === Define Relation ===
const relation = new LinearRelation(group);
const [varX] = relation.allocateScalars(1);
const [varG, varXPoint] = relation.allocateElements(2);
relation.appendEquation(varXPoint, [[varX, varG]]);
relation.setElements([
  [varG, G],
  [varXPoint, X],
]);

// === Non-Interactive Proof (Fiat-Shamir) ===

// Create protocol with optional session ID for domain separation
const sessionId = new TextEncoder().encode('example-session-123');
const ni = new NISigmaProtocol(relation, { sessionId });

// Prover generates proof
console.log('Prover: Generating proof...');
const proof = ni.prove([x]);
const proofBytes = ni.serializeProof(proof);
console.log('Proof size:', proofBytes.length, 'bytes (challenge + response)\n');

// === Simulate Network Transfer ===
console.log('--- Sending proof over network ---\n');

// === Verifier Side ===
// Verifier needs same relation setup and session ID
const relation2 = new LinearRelation(group);
const [varX2] = relation2.allocateScalars(1);
const [varG2, varXPoint2] = relation2.allocateElements(2);
relation2.appendEquation(varXPoint2, [[varX2, varG2]]);
relation2.setElements([
  [varG2, G],
  [varXPoint2, X], // Public X received from prover
]);

const ni2 = new NISigmaProtocol(relation2, { sessionId });

// Deserialize and verify
console.log('Verifier: Verifying proof...');
const receivedProof = ni2.deserializeProof(proofBytes);
const valid = ni2.verify(receivedProof);
console.log('Valid:', valid);

// === Batchable Format ===
console.log('\n=== Batchable Format (for batch verification) ===\n');

const batchableProof = ni.proveBatchable([x]);
const batchableBytes = ni.serializeBatchableProof(batchableProof);
console.log('Batchable proof size:', batchableBytes.length, 'bytes (commitment + response)');

const receivedBatchable = ni2.deserializeBatchableProof(batchableBytes);
const validBatchable = ni2.verifyBatchable(receivedBatchable);
console.log('Valid:', validBatchable);

// === Format Comparison ===
console.log('\n=== Format Comparison ===');
console.log(
  'Challenge-response format:',
  proofBytes.length,
  'bytes (smaller, recomputes commitment)'
);
console.log(
  'Batchable format:',
  batchableBytes.length,
  'bytes (larger, enables batch verification)'
);
