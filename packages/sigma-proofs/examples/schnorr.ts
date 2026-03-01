/**
 * Schnorr Proof Example
 *
 * Proves knowledge of a discrete logarithm:
 *   PoK{(x): X = x·G}
 *
 * Run: npx tsx examples/schnorr.ts
 */

import { LinearRelation, SchnorrProof, ristretto255 } from '../src/index.js';

/** Convert bytes to hex string (Workers-compatible) */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

const group = ristretto255;

// === Setup ===
// Prover knows secret x, public statement is X = x·G

const G = group.generator();
const x = group.randomScalar(); // Prover's secret
const X = G.multiply(x); // Public value

console.log('=== Schnorr Proof: PoK{(x): X = x·G} ===\n');
console.log('Secret x:', toHex(x.toBytes()).slice(0, 16) + '...');
console.log('Public X:', toHex(X.toBytes()).slice(0, 16) + '...\n');

// === Define Relation ===

const relation = new LinearRelation(group);

// Allocate variable indices
const [varX] = relation.allocateScalars(1); // Index for scalar x
const [varG, varXPoint] = relation.allocateElements(2); // Indices for G, X

// Add constraint: X = x·G
// (equation index 0, image is X)
relation.appendEquation(varXPoint, [[varX, varG]]);

// Set concrete element values (image derived automatically from varXPoint in appendEquation)
relation.setElements([
  [varG, G],
  [varXPoint, X],
]);

// === Interactive Proof ===

const proof = new SchnorrProof(relation);

// Step 1: Prover commits
console.log('Step 1: Prover commits...');
const prover = proof.proverCommit([x]);
console.log(
  'Commitment:',
  prover.commitment.map((e) => toHex(e.toBytes()).slice(0, 16) + '...')
);

// Step 2: Verifier sends random challenge
console.log('\nStep 2: Verifier sends challenge...');
const challenge = group.randomScalar();
console.log('Challenge:', toHex(challenge.toBytes()).slice(0, 16) + '...');

// Step 3: Prover responds (one-shot - consumes the state)
console.log('\nStep 3: Prover responds...');
const response = prover.respond(challenge);
console.log(
  'Response:',
  response.map((s) => toHex(s.toBytes()).slice(0, 16) + '...')
);

// Step 4: Verifier checks
console.log('\nStep 4: Verifier checks...');
const valid = proof.verify(prover.commitment, challenge, response);
console.log('Valid:', valid);

// === Serialization ===
console.log('\n=== Serialization ===');
const commitmentBytes = proof.serializeCommitment(prover.commitment);
const responseBytes = proof.serializeResponse(response);
console.log('Commitment size:', commitmentBytes.length, 'bytes (1 element)');
console.log('Response size:', responseBytes.length, 'bytes (1 scalar)');

// Deserialize and verify again
const commitment2 = proof.deserializeCommitment(commitmentBytes);
const response2 = proof.deserializeResponse(responseBytes);
const valid2 = proof.verify(commitment2, challenge, response2);
console.log('Valid after deserialize:', valid2);
