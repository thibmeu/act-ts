/**
 * Test vectors for sigma-proofs
 *
 * Official spec vectors (testSigmaProtocols.json) use BLS12-381 which we don't support.
 * These tests verify correctness via:
 * 1. Deterministic vectors with known scalars
 * 2. Mathematical properties (completeness, soundness)
 * 3. Serialization consistency
 */
import { describe, it, expect } from 'vitest';
import { LinearRelation, SchnorrProof, ristretto255, p256 } from '../src/index.js';
import type { Group, Scalar } from '../src/group.js';

// Test vectors from spec use BLS12-381 - document why they're not directly usable
import specVectors from './vectors/testSigmaProtocols.json';

describe('spec test vectors (BLS12-381)', () => {
  it.todo(
    'discrete_logarithm - requires BLS12-381 ciphersuite (spec uses sigma/OWKeccak1600+Bls12381)'
  );
  it.todo('dleq - requires BLS12-381 ciphersuite');
  it.todo('pedersen_commitment - requires BLS12-381 ciphersuite');

  it('documents spec vector format for future BLS12-381 implementation', () => {
    // Statement format: LE u32 indices + compressed group elements
    // Proof format (batchable): commitment || response (NOT challenge || response)
    // Witness: array of LE scalars
    const dlog = specVectors.discrete_logarithm;
    expect(dlog.Ciphersuite).toBe('sigma/OWKeccak1600+Bls12381');

    // Session ID decodes to test name
    const sessionId = Buffer.from(dlog.SessionId, 'hex').toString('utf8');
    expect(sessionId).toBe('discrete_logarithm');
  });
});

/**
 * Deterministic test vectors for ristretto255
 *
 * These use fixed scalars to create reproducible test cases.
 */
describe('ristretto255 deterministic vectors', () => {
  const group = ristretto255;

  // Fixed test scalars (chosen arbitrarily, small for readability)
  const x_bytes = new Uint8Array(32);
  x_bytes[0] = 42; // x = 42

  const k_bytes = new Uint8Array(32);
  k_bytes[0] = 123; // k = 123 (nonce)

  const c_bytes = new Uint8Array(32);
  c_bytes[0] = 7; // c = 7 (challenge)

  describe('discrete log proof (Schnorr)', () => {
    it('verifies with correct witness', () => {
      const x = group.scalarFromBytes(x_bytes);
      const G = group.generator();
      const X = G.multiply(x);

      const relation = new LinearRelation(group);
      const [varX] = relation.allocateScalars(1);
      const [varG, varXPoint] = relation.allocateElements(2);
      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);
      relation.setImage([[0, X]]);

      const proof = new SchnorrProof(relation);
      const [commitment, state] = proof.proverCommit([x]);
      const challenge = group.scalarFromBytes(c_bytes);
      const response = proof.proverResponse(state, challenge);

      expect(proof.verify(commitment, challenge, response)).toBe(true);
    });

    it('rejects with wrong witness (soundness)', () => {
      const x = group.scalarFromBytes(x_bytes);
      const wrongX = group.scalarFromBigint(999n);
      const G = group.generator();
      const X = G.multiply(x);

      const relation = new LinearRelation(group);
      const [varX] = relation.allocateScalars(1);
      const [varG, varXPoint] = relation.allocateElements(2);
      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);
      relation.setImage([[0, X]]);

      const proof = new SchnorrProof(relation);
      const [commitment, state] = proof.proverCommit([wrongX]);
      const challenge = group.scalarFromBytes(c_bytes);
      const response = proof.proverResponse(state, challenge);

      expect(proof.verify(commitment, challenge, response)).toBe(false);
    });

    it('rejects with wrong challenge (binding)', () => {
      const x = group.scalarFromBytes(x_bytes);
      const G = group.generator();
      const X = G.multiply(x);

      const relation = new LinearRelation(group);
      const [varX] = relation.allocateScalars(1);
      const [varG, varXPoint] = relation.allocateElements(2);
      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);
      relation.setImage([[0, X]]);

      const proof = new SchnorrProof(relation);
      const [commitment, state] = proof.proverCommit([x]);
      const challenge1 = group.scalarFromBytes(c_bytes);
      const challenge2 = group.scalarFromBigint(99n);
      const response = proof.proverResponse(state, challenge1);

      // Verify with different challenge should fail
      expect(proof.verify(commitment, challenge2, response)).toBe(false);
    });
  });

  describe('DLEQ proof', () => {
    it('verifies equality of discrete logs', () => {
      const x = group.scalarFromBytes(x_bytes);
      const G = group.generator();
      const H = G.multiply(group.scalarFromBigint(7n)); // H = 7*G
      const X = G.multiply(x);
      const Y = H.multiply(x);

      const relation = new LinearRelation(group);
      const [varX] = relation.allocateScalars(1);
      const [varG, varH, varXPoint, varYPoint] = relation.allocateElements(4);
      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.appendEquation(varYPoint, [[varX, varH]]);
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
      const [commitment, state] = proof.proverCommit([x]);
      const challenge = group.scalarFromBytes(c_bytes);
      const response = proof.proverResponse(state, challenge);

      expect(proof.verify(commitment, challenge, response)).toBe(true);
    });

    it('rejects when discrete logs differ', () => {
      const x1 = group.scalarFromBytes(x_bytes);
      const x2 = group.scalarFromBigint(999n);
      const G = group.generator();
      const H = G.multiply(group.scalarFromBigint(7n));
      const X = G.multiply(x1);
      const Y = H.multiply(x2); // Different scalar!

      const relation = new LinearRelation(group);
      const [varX] = relation.allocateScalars(1);
      const [varG, varH, varXPoint, varYPoint] = relation.allocateElements(4);
      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.appendEquation(varYPoint, [[varX, varH]]);
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
      // Prover tries with x1, but Y = x2*H
      const [commitment, state] = proof.proverCommit([x1]);
      const challenge = group.scalarFromBytes(c_bytes);
      const response = proof.proverResponse(state, challenge);

      expect(proof.verify(commitment, challenge, response)).toBe(false);
    });
  });

  describe('Pedersen commitment', () => {
    it('verifies knowledge of opening', () => {
      const x = group.scalarFromBytes(x_bytes);
      const r = group.scalarFromBigint(17n);
      const G = group.generator();
      const H = G.multiply(group.scalarFromBigint(11n));
      const C = G.multiply(x).add(H.multiply(r));

      const relation = new LinearRelation(group);
      const [varX, varR] = relation.allocateScalars(2);
      const [varG, varH, varC] = relation.allocateElements(3);
      relation.appendEquation(varC, [
        [varX, varG],
        [varR, varH],
      ]);
      relation.setElements([
        [varG, G],
        [varH, H],
        [varC, C],
      ]);
      relation.setImage([[0, C]]);

      const proof = new SchnorrProof(relation);
      const [commitment, state] = proof.proverCommit([x, r]);
      const challenge = group.scalarFromBytes(c_bytes);
      const response = proof.proverResponse(state, challenge);

      expect(proof.verify(commitment, challenge, response)).toBe(true);
    });
  });
});

/**
 * P-256 deterministic vectors
 */
describe('P-256 deterministic vectors', () => {
  const group = p256;

  const x_bytes = new Uint8Array(32);
  x_bytes[31] = 42; // P-256 uses big-endian, so put value at end

  const c_bytes = new Uint8Array(32);
  c_bytes[31] = 7;

  describe('discrete log proof', () => {
    it('verifies with correct witness', () => {
      const x = group.scalarFromBytes(x_bytes);
      const G = group.generator();
      const X = G.multiply(x);

      const relation = new LinearRelation(group);
      const [varX] = relation.allocateScalars(1);
      const [varG, varXPoint] = relation.allocateElements(2);
      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);
      relation.setImage([[0, X]]);

      const proof = new SchnorrProof(relation);
      const [commitment, state] = proof.proverCommit([x]);
      const challenge = group.scalarFromBytes(c_bytes);
      const response = proof.proverResponse(state, challenge);

      expect(proof.verify(commitment, challenge, response)).toBe(true);
    });

    it('rejects with wrong witness', () => {
      const x = group.scalarFromBytes(x_bytes);
      const wrongX = group.scalarFromBigint(999n);
      const G = group.generator();
      const X = G.multiply(x);

      const relation = new LinearRelation(group);
      const [varX] = relation.allocateScalars(1);
      const [varG, varXPoint] = relation.allocateElements(2);
      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);
      relation.setImage([[0, X]]);

      const proof = new SchnorrProof(relation);
      const [commitment, state] = proof.proverCommit([wrongX]);
      const challenge = group.scalarFromBytes(c_bytes);
      const response = proof.proverResponse(state, challenge);

      expect(proof.verify(commitment, challenge, response)).toBe(false);
    });
  });
});

/**
 * Serialization round-trip tests
 */
describe('serialization', () => {
  const groups: [string, Group][] = [
    ['ristretto255', ristretto255],
    ['P-256', p256],
  ];

  for (const [name, group] of groups) {
    describe(name, () => {
      it('commitment round-trips correctly', () => {
        const x = group.randomScalar();
        const G = group.generator();
        const X = G.multiply(x);

        const relation = new LinearRelation(group);
        const [varX] = relation.allocateScalars(1);
        const [varG, varXPoint] = relation.allocateElements(2);
        relation.appendEquation(varXPoint, [[varX, varG]]);
        relation.setElements([
          [varG, G],
          [varXPoint, X],
        ]);
        relation.setImage([[0, X]]);

        const proof = new SchnorrProof(relation);
        const [commitment] = proof.proverCommit([x]);

        const bytes = proof.serializeCommitment(commitment);
        const restored = proof.deserializeCommitment(bytes);

        expect(restored.length).toBe(commitment.length);
        for (let i = 0; i < commitment.length; i++) {
          expect(restored[i].equals(commitment[i])).toBe(true);
        }
      });

      it('response round-trips correctly', () => {
        const x = group.randomScalar();
        const G = group.generator();
        const X = G.multiply(x);

        const relation = new LinearRelation(group);
        const [varX] = relation.allocateScalars(1);
        const [varG, varXPoint] = relation.allocateElements(2);
        relation.appendEquation(varXPoint, [[varX, varG]]);
        relation.setElements([
          [varG, G],
          [varXPoint, X],
        ]);
        relation.setImage([[0, X]]);

        const proof = new SchnorrProof(relation);
        const [commitment, state] = proof.proverCommit([x]);
        const challenge = group.randomScalar();
        const response = proof.proverResponse(state, challenge);

        const bytes = proof.serializeResponse(response);
        const restored = proof.deserializeResponse(bytes);

        expect(restored.length).toBe(response.length);
        for (let i = 0; i < response.length; i++) {
          expect(restored[i].equals(response[i])).toBe(true);
        }
      });

      it('full proof verifies after serialization round-trip', () => {
        const x = group.randomScalar();
        const G = group.generator();
        const X = G.multiply(x);

        const relation = new LinearRelation(group);
        const [varX] = relation.allocateScalars(1);
        const [varG, varXPoint] = relation.allocateElements(2);
        relation.appendEquation(varXPoint, [[varX, varG]]);
        relation.setElements([
          [varG, G],
          [varXPoint, X],
        ]);
        relation.setImage([[0, X]]);

        const proof = new SchnorrProof(relation);
        const [commitment, state] = proof.proverCommit([x]);
        const challenge = group.randomScalar();
        const response = proof.proverResponse(state, challenge);

        // Serialize and restore
        const commitmentBytes = proof.serializeCommitment(commitment);
        const responseBytes = proof.serializeResponse(response);
        const restoredCommitment = proof.deserializeCommitment(commitmentBytes);
        const restoredResponse = proof.deserializeResponse(responseBytes);

        // Must still verify
        expect(proof.verify(restoredCommitment, challenge, restoredResponse)).toBe(true);
      });
    });
  }
});

/**
 * Mathematical property tests
 */
describe('mathematical properties', () => {
  const group = ristretto255;

  describe('completeness', () => {
    it('honest prover always succeeds with random inputs', () => {
      // Run multiple times to increase confidence
      for (let i = 0; i < 10; i++) {
        const x = group.randomScalar();
        const G = group.generator();
        const X = G.multiply(x);

        const relation = new LinearRelation(group);
        const [varX] = relation.allocateScalars(1);
        const [varG, varXPoint] = relation.allocateElements(2);
        relation.appendEquation(varXPoint, [[varX, varG]]);
        relation.setElements([
          [varG, G],
          [varXPoint, X],
        ]);
        relation.setImage([[0, X]]);

        const proof = new SchnorrProof(relation);
        const [commitment, state] = proof.proverCommit([x]);
        const challenge = group.randomScalar();
        const response = proof.proverResponse(state, challenge);

        expect(proof.verify(commitment, challenge, response)).toBe(true);
      }
    });
  });

  describe('soundness', () => {
    it('dishonest prover fails with overwhelming probability', () => {
      // A prover who doesn't know x cannot produce valid proof
      // (except with negligible probability 1/|F|)
      let failures = 0;
      const trials = 20;

      for (let i = 0; i < trials; i++) {
        const x = group.randomScalar();
        const wrongX = group.randomScalar();
        const G = group.generator();
        const X = G.multiply(x);

        const relation = new LinearRelation(group);
        const [varX] = relation.allocateScalars(1);
        const [varG, varXPoint] = relation.allocateElements(2);
        relation.appendEquation(varXPoint, [[varX, varG]]);
        relation.setElements([
          [varG, G],
          [varXPoint, X],
        ]);
        relation.setImage([[0, X]]);

        const proof = new SchnorrProof(relation);
        const [commitment, state] = proof.proverCommit([wrongX]);
        const challenge = group.randomScalar();
        const response = proof.proverResponse(state, challenge);

        if (!proof.verify(commitment, challenge, response)) {
          failures++;
        }
      }

      // All attempts should fail (soundness)
      expect(failures).toBe(trials);
    });
  });

  describe('special soundness', () => {
    it('two valid responses for same commitment with different challenges reveal witness', () => {
      // This tests the "special soundness" property:
      // Given (commitment, c1, r1) and (commitment, c2, r2) both valid,
      // we can extract witness x = (r1 - r2) / (c1 - c2)

      const x = group.scalarFromBigint(42n);
      const G = group.generator();
      const X = G.multiply(x);

      const relation = new LinearRelation(group);
      const [varX] = relation.allocateScalars(1);
      const [varG, varXPoint] = relation.allocateElements(2);
      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);
      relation.setImage([[0, X]]);

      const proof = new SchnorrProof(relation);

      // Simulate: prover uses same nonce k for two different challenges
      // This is insecure in practice but demonstrates special soundness
      const [commitment, state] = proof.proverCommit([x]);
      const c1 = group.scalarFromBigint(7n);
      const c2 = group.scalarFromBigint(13n);

      const r1 = proof.proverResponse(state, c1);
      // Need fresh state with same nonce - recreate manually
      const r2 = proof.proverResponse({ ...state }, c2);

      // Both should verify
      expect(proof.verify(commitment, c1, r1)).toBe(true);
      expect(proof.verify(commitment, c2, r2)).toBe(true);

      // Extract witness: x = (r1 - r2) / (c1 - c2)
      // r1 = k + c1*x, r2 = k + c2*x
      // r1 - r2 = (c1 - c2)*x
      // x = (r1 - r2) * (c1 - c2)^{-1}

      // Note: We don't have scalar inversion exposed, so we verify
      // the relationship holds: (r1 - r2) = (c1 - c2) * x
      const r1_minus_r2 = r1[0].add(r2[0].neg());
      const c1_minus_c2 = c1.add(c2.neg());
      const expected = c1_minus_c2.mul(x);

      expect(r1_minus_r2.equals(expected)).toBe(true);
    });
  });
});
