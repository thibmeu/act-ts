/**
 * DLEQ (Discrete Log Equality) Proof Example
 *
 * Proves the same secret is used in two discrete log relations:
 *   PoK{(x): X = x·G ∧ Y = x·H}
 *
 * This is useful for:
 * - Proving ElGamal re-encryption correctness
 * - Proving correct Diffie-Hellman key exchange
 * - Linking commitments without revealing the value
 *
 * Run: npx tsx examples/dleq.ts
 */

import { LinearRelation, SchnorrProof, ristretto255 } from '../src/index.js';

const group = ristretto255;

// === Setup ===
// Prover knows x, public statement is: X = x·G AND Y = x·H

const G = group.generator();
const H = G.multiply(group.randomScalar()); // Different generator
const x = group.randomScalar(); // Prover's secret
const X = G.multiply(x);
const Y = H.multiply(x); // Same x!

console.log('=== DLEQ Proof: PoK{(x): X = x·G ∧ Y = x·H} ===\n');
console.log('Proving: X/G = Y/H (same discrete log)\n');

// === Define Relation ===

const relation = new LinearRelation(group);

// Single secret scalar, but used in two equations
const [varX] = relation.allocateScalars(1);
const [varG, varH, varXPoint, varYPoint] = relation.allocateElements(4);

// Constraint 0: X = x·G
relation.appendEquation(varXPoint, [[varX, varG]]);

// Constraint 1: Y = x·H (same varX!)
relation.appendEquation(varYPoint, [[varX, varH]]);

relation.setElements([
  [varG, G],
  [varH, H],
  [varXPoint, X],
  [varYPoint, Y],
]);
// Image derived automatically from appendEquation LHS elements

// === Proof ===

const proof = new SchnorrProof(relation);
const prover = proof.proverCommit([x]);
const challenge = group.randomScalar();
const response = prover.respond(challenge);
const valid = proof.verify(prover.commitment, challenge, response);

console.log('Commitment elements:', prover.commitment.length);
console.log('Response scalars:', response.length);
console.log('Valid:', valid);

// === Negative Test: Different x values ===
console.log('\n=== Negative Test: X = x₁·G, Y = x₂·H (cheating attempt) ===');

// Attacker has X = x₁·G and Y = x₂·H with x₁ ≠ x₂
// They want to prove DLEQ but can't (soundness)

const x1 = group.randomScalar();
const x2 = group.randomScalar(); // Different!
const X2 = G.multiply(x1);
const Y2 = H.multiply(x2); // Uses x2, not x1!

// Set up relation claiming same scalar
const relation2 = new LinearRelation(group);
const [varX_cheat] = relation2.allocateScalars(1);
const [varG2, varH2, varX2Point, varY2Point] = relation2.allocateElements(4);

relation2.appendEquation(varX2Point, [[varX_cheat, varG2]]);
relation2.appendEquation(varY2Point, [[varX_cheat, varH2]]);

relation2.setElements([
  [varG2, G],
  [varH2, H],
  [varX2Point, X2],
  [varY2Point, Y2],
]);
// Image derived automatically

const proof2 = new SchnorrProof(relation2);
// Using x1 as witness, but Y2 = x2·H not x1·H
const prover2 = proof2.proverCommit([x1]);
const challenge2 = group.randomScalar();
const response2 = prover2.respond(challenge2);
const valid2 = proof2.verify(prover2.commitment, challenge2, response2);

console.log('Valid (should be false):', valid2);
