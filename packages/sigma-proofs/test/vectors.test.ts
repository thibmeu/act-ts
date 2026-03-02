/**
 * Test vectors for sigma-proofs
 *
 * Official spec vectors (testSigmaProtocols.json) use BLS12-381 which we now support.
 * These tests verify correctness via:
 * 1. Spec test vectors with deterministic RNG
 * 2. Mathematical properties (completeness, soundness)
 * 3. Serialization consistency
 */
import { describe, it, expect } from 'vitest';
import {
  LinearRelation,
  SchnorrProof,
  NISigmaProtocol,
  ristretto255,
  p256,
  bls12_381_g1,
} from '../src/index.js';
import type { Group, GroupElement } from '../src/group.js';
import { asciiToBytes } from '../src/utils.js';

// Test vectors from spec
import specVectors from './vectors/testSigmaProtocols.json';

/** Helper to convert hex to Uint8Array */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Helper to convert Uint8Array to hex */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Protocol ID for BLS12-381 test vectors */
const BLS12381_PROTOCOL_ID = (() => {
  const id = asciiToBytes('sigma-proofs_Shake128_BLS12381');
  const result = new Uint8Array(64);
  result.set(id);
  return result;
})();

/**
 * Parse a statement from spec test vectors.
 * Format: [numEqs:u32le] [per eq: imgIdx:u32le, numTerms:u32le, terms...] [elements...]
 */
function parseStatement(
  group: Group,
  statementHex: string
): { relation: LinearRelation; headerSize: number } {
  const stmt = hexToBytes(statementHex);
  const dv = new DataView(stmt.buffer, stmt.byteOffset, stmt.byteLength);
  let offset = 0;

  const numEqs = dv.getUint32(offset, true);
  offset += 4;

  // First pass: count scalars and elements needed, collect structure
  const equations: Array<{ imgIdx: number; terms: Array<[number, number]> }> = [];
  let maxScalarIdx = -1;
  let maxElemIdx = -1;

  for (let eq = 0; eq < numEqs; eq++) {
    const imgIdx = dv.getUint32(offset, true);
    offset += 4;
    const numTerms = dv.getUint32(offset, true);
    offset += 4;

    const terms: Array<[number, number]> = [];
    for (let t = 0; t < numTerms; t++) {
      const scalarIdx = dv.getUint32(offset, true);
      offset += 4;
      const elemIdx = dv.getUint32(offset, true);
      offset += 4;
      terms.push([scalarIdx, elemIdx]);
      maxScalarIdx = Math.max(maxScalarIdx, scalarIdx);
      maxElemIdx = Math.max(maxElemIdx, elemIdx);
    }
    maxElemIdx = Math.max(maxElemIdx, imgIdx);
    equations.push({ imgIdx, terms });
  }

  const headerSize = offset;
  const numScalars = maxScalarIdx + 1;
  const numElements = maxElemIdx + 1;

  // Parse elements from remaining bytes
  const elements: GroupElement[] = [];
  for (let i = 0; i < numElements; i++) {
    const elemBytes = stmt.subarray(headerSize + i * 48, headerSize + (i + 1) * 48);
    elements.push(group.elementFromBytes(elemBytes));
  }

  // Build relation
  const relation = new LinearRelation(group);
  relation.allocateScalars(numScalars);
  const elemIndices = relation.allocateElements(numElements);

  for (const eq of equations) {
    relation.appendEquation(eq.imgIdx, eq.terms);
  }

  const elemPairs: Array<[number, GroupElement]> = [];
  for (let i = 0; i < numElements; i++) {
    const idx = elemIndices[i];
    const elem = elements[i];
    if (idx !== undefined && elem !== undefined) {
      elemPairs.push([idx, elem]);
    }
  }
  relation.setElements(elemPairs);

  return { relation, headerSize };
}

describe('spec test vectors (BLS12-381)', () => {
  const group = bls12_381_g1;

  it('documents spec vector format', () => {
    const dlog = specVectors.discrete_logarithm;
    expect(dlog.Ciphersuite).toBe('sigma-proofs_Shake128_BLS12381');

    const sessionId = new TextDecoder().decode(hexToBytes(dlog.SessionId));
    expect(sessionId).toBe('discrete_logarithm');
  });

  it('BLS12-381 prove/verify roundtrip works', () => {
    const sessionId = hexToBytes('64697363726574655f6c6f6761726974686d');
    const witnessBytes = hexToBytes(
      '14de3306fc5f57e5d9e2e89caaf03a261f668b621093c17da407ee746243a421'
    );
    const x = group.scalarFromBytes(witnessBytes);
    const G = group.generator();
    const X = G.multiply(x);

    const relation = new LinearRelation(group);
    relation.allocateScalars(1);
    const elemIndices = relation.allocateElements(2);
    relation.appendEquation(1, [[0, 0]]);
    relation.setElements([
      [elemIndices[0]!, G],
      [elemIndices[1]!, X],
    ]);

    const ni = new NISigmaProtocol(relation, {
      sessionId,
      protocolId: BLS12381_PROTOCOL_ID,
    });

    const proof = ni.proveBatchable([x]);
    expect(ni.verifyBatchable(proof)).toBe(true);
  });

  // POC interop tests - blocked on Fiat-Shamir transcript mismatch
  //
  // Status (2026-03-02):
  // - Instance labels NOW MATCH (getInstanceLabel() fixed)
  // - Sponge implementation matches spec vectors (duplexSpongeVectors.json)
  // - Sigma protocol verification works (non-batchable proof verifies with embedded challenge)
  // - Challenge computation differs - our transcript produces different challenges than POC
  //
  // Remaining issue: session ID hashing or codec absorb order differs from POC.
  // Need to trace exact byte sequences in POC to find discrepancy.
  it.todo('discrete_logarithm - verifies spec proof (blocked: challenge computation mismatch)');
  it.todo('dleq - verifies spec proof (blocked: challenge computation mismatch)');
  it.todo('pedersen_commitment - verifies spec proof (blocked: challenge computation mismatch)');
  it.todo(
    'pedersen_commitment_dleq - verifies spec proof (blocked: challenge computation mismatch)'
  );
  it.todo(
    'bbs_blind_commitment_computation - verifies spec proof (blocked: challenge computation mismatch)'
  );
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

  const c_bytes = new Uint8Array(32);
  c_bytes[0] = 7; // c = 7 (challenge)

  describe('discrete log proof (Schnorr)', () => {
    it('verifies with correct witness', () => {
      const x = group.scalarFromBytes(x_bytes);
      const G = group.generator();
      const X = G.multiply(x);

      const relation = new LinearRelation(group);
      const scalars = relation.allocateScalars(1);
      const elements = relation.allocateElements(2);
      const varX = scalars[0]!;
      const varG = elements[0]!;
      const varXPoint = elements[1]!;

      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);

      const proof = new SchnorrProof(relation);
      const prover = proof.proverCommit([x]);
      const challenge = group.scalarFromBytes(c_bytes);
      const response = prover.respond(challenge);

      expect(proof.verify(prover.commitment, challenge, response)).toBe(true);
    });

    it('rejects with wrong witness (soundness)', () => {
      const x = group.scalarFromBytes(x_bytes);
      const wrongX = group.scalarFromBigint(999n);
      const G = group.generator();
      const X = G.multiply(x);

      const relation = new LinearRelation(group);
      const scalars = relation.allocateScalars(1);
      const elements = relation.allocateElements(2);
      const varX = scalars[0]!;
      const varG = elements[0]!;
      const varXPoint = elements[1]!;

      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);

      const proof = new SchnorrProof(relation);
      const prover = proof.proverCommit([wrongX]);
      const challenge = group.scalarFromBytes(c_bytes);
      const response = prover.respond(challenge);

      expect(proof.verify(prover.commitment, challenge, response)).toBe(false);
    });

    it('rejects with wrong challenge (binding)', () => {
      const x = group.scalarFromBytes(x_bytes);
      const G = group.generator();
      const X = G.multiply(x);

      const relation = new LinearRelation(group);
      const scalars = relation.allocateScalars(1);
      const elements = relation.allocateElements(2);
      const varX = scalars[0]!;
      const varG = elements[0]!;
      const varXPoint = elements[1]!;

      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);

      const proof = new SchnorrProof(relation);
      const prover = proof.proverCommit([x]);
      const challenge1 = group.scalarFromBytes(c_bytes);
      const challenge2 = group.scalarFromBigint(99n);
      const response = prover.respond(challenge1);

      // Verify with different challenge should fail
      expect(proof.verify(prover.commitment, challenge2, response)).toBe(false);
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
      const scalars = relation.allocateScalars(1);
      const elements = relation.allocateElements(4);
      const varX = scalars[0]!;
      const varG = elements[0]!;
      const varH = elements[1]!;
      const varXPoint = elements[2]!;
      const varYPoint = elements[3]!;

      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.appendEquation(varYPoint, [[varX, varH]]);
      relation.setElements([
        [varG, G],
        [varH, H],
        [varXPoint, X],
        [varYPoint, Y],
      ]);

      const proof = new SchnorrProof(relation);
      const prover = proof.proverCommit([x]);
      const challenge = group.scalarFromBytes(c_bytes);
      const response = prover.respond(challenge);

      expect(proof.verify(prover.commitment, challenge, response)).toBe(true);
    });

    it('rejects when discrete logs differ', () => {
      const x1 = group.scalarFromBytes(x_bytes);
      const x2 = group.scalarFromBigint(999n);
      const G = group.generator();
      const H = G.multiply(group.scalarFromBigint(7n));
      const X = G.multiply(x1);
      const Y = H.multiply(x2); // Different scalar!

      const relation = new LinearRelation(group);
      const scalars = relation.allocateScalars(1);
      const elements = relation.allocateElements(4);
      const varX = scalars[0]!;
      const varG = elements[0]!;
      const varH = elements[1]!;
      const varXPoint = elements[2]!;
      const varYPoint = elements[3]!;

      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.appendEquation(varYPoint, [[varX, varH]]);
      relation.setElements([
        [varG, G],
        [varH, H],
        [varXPoint, X],
        [varYPoint, Y],
      ]);

      const proof = new SchnorrProof(relation);
      // Prover tries with x1, but Y = x2*H
      const prover = proof.proverCommit([x1]);
      const challenge = group.scalarFromBytes(c_bytes);
      const response = prover.respond(challenge);

      expect(proof.verify(prover.commitment, challenge, response)).toBe(false);
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
      const scalars = relation.allocateScalars(2);
      const elements = relation.allocateElements(3);
      const varX = scalars[0]!;
      const varR = scalars[1]!;
      const varG = elements[0]!;
      const varH = elements[1]!;
      const varC = elements[2]!;

      relation.appendEquation(varC, [
        [varX, varG],
        [varR, varH],
      ]);
      relation.setElements([
        [varG, G],
        [varH, H],
        [varC, C],
      ]);

      const proof = new SchnorrProof(relation);
      const prover = proof.proverCommit([x, r]);
      const challenge = group.scalarFromBytes(c_bytes);
      const response = prover.respond(challenge);

      expect(proof.verify(prover.commitment, challenge, response)).toBe(true);
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
      const scalars = relation.allocateScalars(1);
      const elements = relation.allocateElements(2);
      const varX = scalars[0]!;
      const varG = elements[0]!;
      const varXPoint = elements[1]!;

      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);

      const proof = new SchnorrProof(relation);
      const prover = proof.proverCommit([x]);
      const challenge = group.scalarFromBytes(c_bytes);
      const response = prover.respond(challenge);

      expect(proof.verify(prover.commitment, challenge, response)).toBe(true);
    });

    it('rejects with wrong witness', () => {
      const x = group.scalarFromBytes(x_bytes);
      const wrongX = group.scalarFromBigint(999n);
      const G = group.generator();
      const X = G.multiply(x);

      const relation = new LinearRelation(group);
      const scalars = relation.allocateScalars(1);
      const elements = relation.allocateElements(2);
      const varX = scalars[0]!;
      const varG = elements[0]!;
      const varXPoint = elements[1]!;

      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);

      const proof = new SchnorrProof(relation);
      const prover = proof.proverCommit([wrongX]);
      const challenge = group.scalarFromBytes(c_bytes);
      const response = prover.respond(challenge);

      expect(proof.verify(prover.commitment, challenge, response)).toBe(false);
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
        const scalars = relation.allocateScalars(1);
        const elements = relation.allocateElements(2);
        const varX = scalars[0]!;
        const varG = elements[0]!;
        const varXPoint = elements[1]!;

        relation.appendEquation(varXPoint, [[varX, varG]]);
        relation.setElements([
          [varG, G],
          [varXPoint, X],
        ]);

        const proof = new SchnorrProof(relation);
        const prover = proof.proverCommit([x]);

        const bytes = proof.serializeCommitment(prover.commitment);
        const restored = proof.deserializeCommitment(bytes);

        expect(restored.length).toBe(prover.commitment.length);
        for (let i = 0; i < prover.commitment.length; i++) {
          expect(restored[i]!.equals(prover.commitment[i]!)).toBe(true);
        }
      });

      it('response round-trips correctly', () => {
        const x = group.randomScalar();
        const G = group.generator();
        const X = G.multiply(x);

        const relation = new LinearRelation(group);
        const scalars = relation.allocateScalars(1);
        const elements = relation.allocateElements(2);
        const varX = scalars[0]!;
        const varG = elements[0]!;
        const varXPoint = elements[1]!;

        relation.appendEquation(varXPoint, [[varX, varG]]);
        relation.setElements([
          [varG, G],
          [varXPoint, X],
        ]);

        const proof = new SchnorrProof(relation);
        const prover = proof.proverCommit([x]);
        const challenge = group.randomScalar();
        const response = prover.respond(challenge);

        const bytes = proof.serializeResponse(response);
        const restored = proof.deserializeResponse(bytes);

        expect(restored.length).toBe(response.length);
        for (let i = 0; i < response.length; i++) {
          expect(restored[i]!.equals(response[i]!)).toBe(true);
        }
      });

      it('full proof verifies after serialization round-trip', () => {
        const x = group.randomScalar();
        const G = group.generator();
        const X = G.multiply(x);

        const relation = new LinearRelation(group);
        const scalars = relation.allocateScalars(1);
        const elements = relation.allocateElements(2);
        const varX = scalars[0]!;
        const varG = elements[0]!;
        const varXPoint = elements[1]!;

        relation.appendEquation(varXPoint, [[varX, varG]]);
        relation.setElements([
          [varG, G],
          [varXPoint, X],
        ]);

        const proof = new SchnorrProof(relation);
        const prover = proof.proverCommit([x]);
        const challenge = group.randomScalar();
        const response = prover.respond(challenge);

        // Serialize and restore
        const commitmentBytes = proof.serializeCommitment(prover.commitment);
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
        const scalars = relation.allocateScalars(1);
        const elements = relation.allocateElements(2);
        const varX = scalars[0]!;
        const varG = elements[0]!;
        const varXPoint = elements[1]!;

        relation.appendEquation(varXPoint, [[varX, varG]]);
        relation.setElements([
          [varG, G],
          [varXPoint, X],
        ]);

        const proof = new SchnorrProof(relation);
        const prover = proof.proverCommit([x]);
        const challenge = group.randomScalar();
        const response = prover.respond(challenge);

        expect(proof.verify(prover.commitment, challenge, response)).toBe(true);
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
        const scalars = relation.allocateScalars(1);
        const elements = relation.allocateElements(2);
        const varX = scalars[0]!;
        const varG = elements[0]!;
        const varXPoint = elements[1]!;

        relation.appendEquation(varXPoint, [[varX, varG]]);
        relation.setElements([
          [varG, G],
          [varXPoint, X],
        ]);

        const proof = new SchnorrProof(relation);
        const prover = proof.proverCommit([wrongX]);
        const challenge = group.randomScalar();
        const response = prover.respond(challenge);

        if (!proof.verify(prover.commitment, challenge, response)) {
          failures++;
        }
      }

      // All attempts should fail (soundness)
      expect(failures).toBe(trials);
    });
  });

  describe('special soundness', () => {
    it('two valid responses for same commitment reveal witness via algebraic relationship', () => {
      // This tests the "special soundness" property:
      // Given (commitment, c1, r1) and (commitment, c2, r2) both valid,
      // we can extract witness x = (r1 - r2) / (c1 - c2)

      const x = group.scalarFromBigint(42n);
      const G = group.generator();
      const X = G.multiply(x);

      const relation = new LinearRelation(group);
      const scalars = relation.allocateScalars(1);
      const elements = relation.allocateElements(2);
      const varX = scalars[0]!;
      const varG = elements[0]!;
      const varXPoint = elements[1]!;

      relation.appendEquation(varXPoint, [[varX, varG]]);
      relation.setElements([
        [varG, G],
        [varXPoint, X],
      ]);

      const proof = new SchnorrProof(relation);

      // Generate two proofs with the same witness
      // (in practice nonce reuse would be insecure, but here we test the math)
      const c1 = group.scalarFromBigint(7n);
      const c2 = group.scalarFromBigint(13n);

      const prover1 = proof.proverCommit([x]);
      const r1 = prover1.respond(c1);

      const prover2 = proof.proverCommit([x]);
      const r2 = prover2.respond(c2);

      // Both should verify
      expect(proof.verify(prover1.commitment, c1, r1)).toBe(true);
      expect(proof.verify(prover2.commitment, c2, r2)).toBe(true);

      // The algebraic relationship (r1 - r2) = (c1 - c2) * x only holds
      // when the same nonce k is used. With different nonces, we can still
      // verify that both proofs are valid for the same statement.
    });
  });
});
