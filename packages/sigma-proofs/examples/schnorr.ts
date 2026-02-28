/**
 * Schnorr Proof Example
 *
 * Proves knowledge of a discrete logarithm:
 *   PoK{(x): X = x·G}
 *
 * Run: npx tsx examples/schnorr.ts
 */

import { LinearRelation, SchnorrProof, ristretto255 } from '../src/index.js';

const group = ristretto255;

// === Setup ===
// Prover knows secret x, public statement is X = x·G

const G = group.generator();
const x = group.randomScalar(); // Prover's secret
const X = G.multiply(x); // Public value

console.log('=== Schnorr Proof: PoK{(x): X = x·G} ===\n');
console.log('Secret x:', Buffer.from(x.toBytes()).toString('hex').slice(0, 16) + '...');
console.log('Public X:', Buffer.from(X.toBytes()).toString('hex').slice(0, 16) + '...\n');

// === Define Relation ===

const relation = new LinearRelation(group);

// Allocate variable indices
const [varX] = relation.allocateScalars(1); // Index for scalar x
const [varG, varXPoint] = relation.allocateElements(2); // Indices for G, X

// Add constraint: X = x·G
// (equation index 0, image is X)
relation.appendEquation(varXPoint, [[varX, varG]]);

// Set concrete element values
relation.setElements([
  [varG, G],
  [varXPoint, X],
]);
relation.setImage([[0, X]]); // Constraint 0's image is X

// === Interactive Proof ===

const proof = new SchnorrProof(relation);

// Step 1: Prover commits
console.log('Step 1: Prover commits...');
const [commitment, proverState] = proof.proverCommit([x]);
console.log(
  'Commitment:',
  commitment.map((e) => Buffer.from(e.toBytes()).toString('hex').slice(0, 16) + '...'),
);

// Step 2: Verifier sends random challenge
console.log('\nStep 2: Verifier sends challenge...');
const challenge = group.randomScalar();
console.log('Challenge:', Buffer.from(challenge.toBytes()).toString('hex').slice(0, 16) + '...');

// Step 3: Prover responds
console.log('\nStep 3: Prover responds...');
const response = proof.proverResponse(proverState, challenge);
console.log(
  'Response:',
  response.map((s) => Buffer.from(s.toBytes()).toString('hex').slice(0, 16) + '...'),
);

// Step 4: Verifier checks
console.log('\nStep 4: Verifier checks...');
const valid = proof.verify(commitment, challenge, response);
console.log('Valid:', valid);

// === Serialization ===
console.log('\n=== Serialization ===');
const commitmentBytes = proof.serializeCommitment(commitment);
const responseBytes = proof.serializeResponse(response);
console.log('Commitment size:', commitmentBytes.length, 'bytes (1 element)');
console.log('Response size:', responseBytes.length, 'bytes (1 scalar)');

// Deserialize and verify again
const commitment2 = proof.deserializeCommitment(commitmentBytes);
const response2 = proof.deserializeResponse(responseBytes);
const valid2 = proof.verify(commitment2, challenge, response2);
console.log('Valid after deserialize:', valid2);
