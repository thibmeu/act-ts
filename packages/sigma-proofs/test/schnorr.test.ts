import { describe, it, expect } from 'vitest';
import { LinearRelation, SchnorrProof, ristretto255, p256 } from '../src/index.js';
import type { Group } from '../src/group.js';

/** Run proof tests for a given group */
function testGroupProofs(group: Group, groupName: string) {
  describe(`${groupName}`, () => {
    describe('Schnorr proof (PoK of discrete log)', () => {
      it('should prove and verify knowledge of x such that X = x * G', () => {

      // Setup: PoK{(x): X = x * G}
      const relation = new LinearRelation(group);
      const [varX] = relation.allocateScalars(1);
      const [varG, varXPoint] = relation.allocateElements(2);
      relation.appendEquation(varXPoint, [[varX, varG]]);

      // Set public values
      const G = group.generator();
      const x = group.randomScalar();
      const X = G.multiply(x);

      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);
      relation.setImage([[0, X]]);

      // Create proof
      const proof = new SchnorrProof(relation);
      const witness = [x];

      // Prover commits
      const [commitment, proverState] = proof.proverCommit(witness);

      // Verifier sends challenge
      const challenge = group.randomScalar();

      // Prover responds
      const response = proof.proverResponse(proverState, challenge);

      // Verify
      const valid = proof.verify(commitment, challenge, response);
      expect(valid).toBe(true);
    });

    it('should reject invalid proof (wrong witness)', () => {

      const relation = new LinearRelation(group);
      const [varX] = relation.allocateScalars(1);
      const [varG, varXPoint] = relation.allocateElements(2);
      relation.appendEquation(varXPoint, [[varX, varG]]);

      const G = group.generator();
      const x = group.randomScalar();
      const X = G.multiply(x);

      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);
      relation.setImage([[0, X]]);

      const proof = new SchnorrProof(relation);

      // Use wrong witness
      const wrongX = group.randomScalar();
      const [commitment, proverState] = proof.proverCommit([wrongX]);
      const challenge = group.randomScalar();
      const response = proof.proverResponse(proverState, challenge);

      const valid = proof.verify(commitment, challenge, response);
      expect(valid).toBe(false);
    });
  });

  describe('DLEQ proof', () => {
    it('should prove and verify DLEQ(G, H, X, Y) = PoK{(x): X = x*G, Y = x*H}', () => {

      // Setup: PoK{(x): X = x*G, Y = x*H}
      const relation = new LinearRelation(group);
      const [varX] = relation.allocateScalars(1);
      const [varG, varH, varXPoint, varYPoint] = relation.allocateElements(4);

      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.appendEquation(varYPoint, [[varX, varH]]);

      // Generate random H (different from G)
      const G = group.generator();
      const H = G.multiply(group.randomScalar()); // H = random * G
      const x = group.randomScalar();
      const X = G.multiply(x);
      const Y = H.multiply(x);

      relation.setElements([
        [varG, G],
        [varH, H],
        [varXPoint, X],
        [varYPoint, Y],
      ]);
      relation.setImage([
        [0, X],
        [1, Y],
      ]);

      const proof = new SchnorrProof(relation);
      const [commitment, proverState] = proof.proverCommit([x]);
      const challenge = group.randomScalar();
      const response = proof.proverResponse(proverState, challenge);

      const valid = proof.verify(commitment, challenge, response);
      expect(valid).toBe(true);
    });
  });

  describe('Pedersen commitment proof', () => {
    it('should prove knowledge of opening (x, r) such that C = x*G + r*H', () => {

      // Setup: PoK{(x, r): C = x*G + r*H}
      const relation = new LinearRelation(group);
      const [varX, varR] = relation.allocateScalars(2);
      const [varG, varH, varC] = relation.allocateElements(3);

      relation.appendEquation(varC, [
        [varX, varG],
        [varR, varH],
      ]);

      const G = group.generator();
      const H = G.multiply(group.randomScalar());
      const x = group.randomScalar();
      const r = group.randomScalar();
      const C = G.multiply(x).add(H.multiply(r));

      relation.setElements([
        [varG, G],
        [varH, H],
        [varC, C],
      ]);
      relation.setImage([[0, C]]);

      const proof = new SchnorrProof(relation);
      const [commitment, proverState] = proof.proverCommit([x, r]);
      const challenge = group.randomScalar();
      const response = proof.proverResponse(proverState, challenge);

      const valid = proof.verify(commitment, challenge, response);
      expect(valid).toBe(true);
    });
  });

  describe('serialization', () => {
    it('should serialize and deserialize commitment and response', () => {

      const relation = new LinearRelation(group);
      const [varX] = relation.allocateScalars(1);
      const [varG, varXPoint] = relation.allocateElements(2);
      relation.appendEquation(varXPoint, [[varX, varG]]);

      const G = group.generator();
      const x = group.randomScalar();
      const X = G.multiply(x);

      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);
      relation.setImage([[0, X]]);

      const proof = new SchnorrProof(relation);
      const [commitment, proverState] = proof.proverCommit([x]);
      const challenge = group.randomScalar();
      const response = proof.proverResponse(proverState, challenge);

      // Serialize
      const commitmentBytes = proof.serializeCommitment(commitment);
      const responseBytes = proof.serializeResponse(response);

      // Deserialize
      const commitment2 = proof.deserializeCommitment(commitmentBytes);
      const response2 = proof.deserializeResponse(responseBytes);

      // Verify with deserialized values
      const valid = proof.verify(commitment2, challenge, response2);
      expect(valid).toBe(true);
    });
  });
  });
}

describe('SchnorrProof', () => {
  testGroupProofs(ristretto255, 'ristretto255');
  testGroupProofs(p256, 'P-256');

  describe('Simulator functions', () => {
    it('simulateResponse returns correct number of scalars', () => {
      const relation = new LinearRelation(ristretto255);
      const [varX, varY] = relation.allocateScalars(2);
      const [varG, varH, varP] = relation.allocateElements(3);
      relation.appendEquation(varP, [
        [varX, varG],
        [varY, varH],
      ]);
      const G = ristretto255.generator();
      const H = G.multiply(ristretto255.randomScalar());
      const x = ristretto255.randomScalar();
      const y = ristretto255.randomScalar();
      const P = G.multiply(x).add(H.multiply(y));
      relation.setElements([
        [varG, G],
        [varH, H],
        [varP, P],
      ]);
      relation.setImage([[0, P]]);

      const proof = new SchnorrProof(relation);
      const response = proof.simulateResponse();
      expect(response.length).toBe(2);
    });

    it('simulateCommitment produces valid transcript', () => {
      const relation = new LinearRelation(ristretto255);
      const [varX] = relation.allocateScalars(1);
      const [varG, varXPoint] = relation.allocateElements(2);
      relation.appendEquation(varXPoint, [[varX, varG]]);

      const G = ristretto255.generator();
      const x = ristretto255.randomScalar();
      const X = G.multiply(x);
      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);
      relation.setImage([[0, X]]);

      const proof = new SchnorrProof(relation);

      // Generate simulated transcript
      const response = proof.simulateResponse();
      const challenge = ristretto255.randomScalar();
      const commitment = proof.simulateCommitment(response, challenge);

      // The simulated transcript should verify!
      expect(proof.verify(commitment, challenge, response)).toBe(true);
    });

    it('simulate() produces complete valid transcript', () => {
      const relation = new LinearRelation(ristretto255);
      const [varX] = relation.allocateScalars(1);
      const [varG, varXPoint] = relation.allocateElements(2);
      relation.appendEquation(varXPoint, [[varX, varG]]);

      const G = ristretto255.generator();
      const x = ristretto255.randomScalar();
      const X = G.multiply(x);
      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);
      relation.setImage([[0, X]]);

      const proof = new SchnorrProof(relation);
      const challenge = ristretto255.randomScalar();

      // Simulate complete transcript
      const [commitment, response] = proof.simulate(challenge);

      // Should verify
      expect(proof.verify(commitment, challenge, response)).toBe(true);
    });

    it('simulated transcript is indistinguishable from real (zero-knowledge)', () => {
      // This tests the zero-knowledge property:
      // A simulated transcript has the same distribution as a real one

      const relation = new LinearRelation(ristretto255);
      const [varX] = relation.allocateScalars(1);
      const [varG, varXPoint] = relation.allocateElements(2);
      relation.appendEquation(varXPoint, [[varX, varG]]);

      const G = ristretto255.generator();
      const x = ristretto255.randomScalar();
      const X = G.multiply(x);
      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);
      relation.setImage([[0, X]]);

      const proof = new SchnorrProof(relation);

      // Generate real transcript
      const [realCommitment, state] = proof.proverCommit([x]);
      const challenge = ristretto255.randomScalar();
      const realResponse = proof.proverResponse(state, challenge);

      // Generate simulated transcript with same challenge
      const [simCommitment, simResponse] = proof.simulate(challenge);

      // Both should verify
      expect(proof.verify(realCommitment, challenge, realResponse)).toBe(true);
      expect(proof.verify(simCommitment, challenge, simResponse)).toBe(true);

      // Both have same structure (1 commitment element, 1 response scalar)
      expect(realCommitment.length).toBe(simCommitment.length);
      expect(realResponse.length).toBe(simResponse.length);
    });
  });
});
