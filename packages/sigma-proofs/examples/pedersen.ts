/**
 * Pedersen Commitment Opening Proof Example
 *
 * Proves knowledge of a commitment opening:
 *   PoK{(x, r): C = x·G + r·H}
 *
 * Pedersen commitments are:
 * - Perfectly hiding: C reveals nothing about x
 * - Computationally binding: can't open to different value
 *
 * Run: npx tsx examples/pedersen.ts
 */

import { LinearRelation, SchnorrProof, ristretto255 } from '../src/index.js';

const group = ristretto255;

// === Setup ===
// Prover has committed value x with randomness r
// C = x·G + r·H

const G = group.generator();
const H = G.multiply(group.randomScalar()); // Blinding generator

const x = group.scalarFromBigint(42n); // The committed value
const r = group.randomScalar(); // Blinding factor

// Compute commitment
const C = G.multiply(x).add(H.multiply(r));

console.log('=== Pedersen Commitment: PoK{(x, r): C = x·G + r·H} ===\n');
console.log('Committed value x = 42');
console.log('Commitment C:', Buffer.from(C.toBytes()).toString('hex').slice(0, 32) + '...\n');

// === Define Relation ===

const relation = new LinearRelation(group);

// Two secret scalars: x (value) and r (randomness)
const [varX, varR] = relation.allocateScalars(2);
const [varG, varH, varC] = relation.allocateElements(3);

// Single constraint: C = x·G + r·H
relation.appendEquation(varC, [
  [varX, varG], // x·G term
  [varR, varH], // r·H term
]);

relation.setElements([
  [varG, G],
  [varH, H],
  [varC, C],
]);
// Image derived automatically from varC in appendEquation

// === Proof ===

const proof = new SchnorrProof(relation);

// Witness: [x, r]
const prover = proof.proverCommit([x, r]);
const challenge = group.randomScalar();
const response = prover.respond(challenge);
const valid = proof.verify(prover.commitment, challenge, response);

console.log('Witness scalars:', 2);
console.log('Commitment elements:', prover.commitment.length);
console.log('Response scalars:', response.length);
console.log('Valid:', valid);

// === Application: Prove equality of committed values ===
console.log('\n=== Extended: Prove two commitments hide same value ===');
console.log('PoK{(x, r₁, r₂): C₁ = x·G + r₁·H ∧ C₂ = x·G + r₂·H}\n');

// Two commitments to the same value x
const r1 = group.randomScalar();
const r2 = group.randomScalar();
const C1 = G.multiply(x).add(H.multiply(r1));
const C2 = G.multiply(x).add(H.multiply(r2));

const relation2 = new LinearRelation(group);

// x is shared, r1 and r2 are separate
const [varX2, varR1, varR2] = relation2.allocateScalars(3);
const [varG3, varH3, varC1, varC2_2] = relation2.allocateElements(4);

// C₁ = x·G + r₁·H
relation2.appendEquation(varC1, [
  [varX2, varG3],
  [varR1, varH3],
]);

// C₂ = x·G + r��·H (same varX2!)
relation2.appendEquation(varC2_2, [
  [varX2, varG3],
  [varR2, varH3],
]);

relation2.setElements([
  [varG3, G],
  [varH3, H],
  [varC1, C1],
  [varC2_2, C2],
]);
// Image derived automatically

const proof2 = new SchnorrProof(relation2);
const prover2 = proof2.proverCommit([x, r1, r2]);
const challenge2 = group.randomScalar();
const response2 = prover2.respond(challenge2);
const valid2 = proof2.verify(prover2.commitment, challenge2, response2);

console.log('Proves: C₁ and C�� commit to same value');
console.log('Without revealing: the value itself or the randomness');
console.log('Valid:', valid2);
