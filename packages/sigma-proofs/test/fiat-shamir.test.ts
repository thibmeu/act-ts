/**
 * Tests for Fiat-Shamir transformation.
 *
 * Tests draft-irtf-cfrg-fiat-shamir-01 implementation.
 */

import { describe, it, expect } from 'vitest';
import {
  Shake128Sponge,
  ByteCodec,
  NISigmaProtocol,
} from '../src/fiat-shamir/index.js';
import { LinearRelation } from '../src/linear-relation.js';
import { ristretto255 } from '../src/ciphersuites/ristretto255.js';
import { p256 } from '../src/ciphersuites/p256.js';

describe('Shake128Sponge', () => {
  it('produces deterministic output for same input', () => {
    const iv = new Uint8Array(64).fill(0x42);
    const sponge1 = new Shake128Sponge(iv);
    const sponge2 = new Shake128Sponge(iv);

    sponge1.absorb(new Uint8Array([1, 2, 3]));
    sponge2.absorb(new Uint8Array([1, 2, 3]));

    const out1 = sponge1.squeeze(32);
    const out2 = sponge2.squeeze(32);

    expect(out1).toEqual(out2);
  });

  it('produces different output for different IVs', () => {
    const iv1 = new Uint8Array(64).fill(0x00);
    const iv2 = new Uint8Array(64).fill(0x01);

    const sponge1 = new Shake128Sponge(iv1);
    const sponge2 = new Shake128Sponge(iv2);

    const out1 = sponge1.squeeze(32);
    const out2 = sponge2.squeeze(32);

    expect(out1).not.toEqual(out2);
  });

  it('produces different output for different absorbed data', () => {
    const iv = new Uint8Array(64);
    const sponge1 = new Shake128Sponge(iv);
    const sponge2 = new Shake128Sponge(iv);

    sponge1.absorb(new Uint8Array([1, 2, 3]));
    sponge2.absorb(new Uint8Array([4, 5, 6]));

    const out1 = sponge1.squeeze(32);
    const out2 = sponge2.squeeze(32);

    expect(out1).not.toEqual(out2);
  });

  it('clone preserves state', () => {
    const iv = new Uint8Array(64).fill(0x42);
    const sponge = new Shake128Sponge(iv);
    sponge.absorb(new Uint8Array([1, 2, 3]));

    const cloned = sponge.clone();

    // Both should produce same output
    const out1 = sponge.squeeze(32);
    const out2 = cloned.squeeze(32);

    expect(out1).toEqual(out2);
  });

  it('squeeze can be called multiple times', () => {
    const iv = new Uint8Array(64);
    const sponge = new Shake128Sponge(iv);
    sponge.absorb(new Uint8Array([1, 2, 3]));

    // Multiple squeezes should give same result (we clone internally)
    const out1 = sponge.squeeze(32);
    const out2 = sponge.squeeze(32);

    expect(out1).toEqual(out2);
  });
});

describe('ByteCodec', () => {
  it('squeezeChallenge returns valid scalar', () => {
    const iv = new Uint8Array(64);
    const sponge = new Shake128Sponge(iv);
    const codec = new ByteCodec(ristretto255, sponge);

    const challenge = codec.squeezeChallenge();

    // Should be a valid scalar (not zero for random squeeze)
    expect(challenge.toBytes().length).toBe(ristretto255.scalarSize);
  });

  it('absorbing elements affects challenge', () => {
    const iv = new Uint8Array(64);
    const G = ristretto255.generator();
    const H = G.multiply(ristretto255.randomScalar());

    const sponge1 = new Shake128Sponge(iv);
    const sponge2 = new Shake128Sponge(iv);
    const codec1 = new ByteCodec(ristretto255, sponge1);
    const codec2 = new ByteCodec(ristretto255, sponge2);

    codec1.absorbElements([G]);
    codec2.absorbElements([H]);

    const c1 = codec1.squeezeChallenge();
    const c2 = codec2.squeezeChallenge();

    expect(c1.equals(c2)).toBe(false);
  });

  it('clone preserves state', () => {
    const iv = new Uint8Array(64);
    const sponge = new Shake128Sponge(iv);
    const codec = new ByteCodec(ristretto255, sponge);

    codec.absorbElements([ristretto255.generator()]);
    const cloned = codec.clone();

    const c1 = codec.squeezeChallenge();
    const c2 = cloned.squeezeChallenge();

    expect(c1.equals(c2)).toBe(true);
  });
});

/** Helper to create a simple Schnorr relation: PoK{(x): X = x*G} */
function createSchnorrRelation(
  group: typeof ristretto255 | typeof p256,
  x: ReturnType<typeof group.randomScalar>
) {
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

  return relation;
}

describe('NISigmaProtocol', () => {
  describe('with ristretto255', () => {
    it('prove/verify roundtrip (challenge-response format)', () => {
      // Simple Schnorr: prove knowledge of x such that X = x*G
      const x = ristretto255.randomScalar();
      const relation = createSchnorrRelation(ristretto255, x);

      const ni = new NISigmaProtocol(relation);
      const proof = ni.prove([x]);

      expect(ni.verify(proof)).toBe(true);
    });

    it('prove/verify roundtrip (batchable format)', () => {
      const x = ristretto255.randomScalar();
      const relation = createSchnorrRelation(ristretto255, x);

      const ni = new NISigmaProtocol(relation);
      const proof = ni.proveBatchable([x]);

      expect(ni.verifyBatchable(proof)).toBe(true);
    });

    it('verification fails for wrong witness', () => {
      const x = ristretto255.randomScalar();
      const wrongX = ristretto255.randomScalar();
      const relation = createSchnorrRelation(ristretto255, x);

      const ni = new NISigmaProtocol(relation);
      const proof = ni.prove([wrongX]); // Wrong witness

      expect(ni.verify(proof)).toBe(false);
    });

    it('serialization roundtrip (challenge-response)', () => {
      const x = ristretto255.randomScalar();
      const relation = createSchnorrRelation(ristretto255, x);

      const ni = new NISigmaProtocol(relation);
      const proof = ni.prove([x]);

      const bytes = ni.serializeProof(proof);
      const deserialized = ni.deserializeProof(bytes);

      expect(deserialized.challenge.equals(proof.challenge)).toBe(true);
      expect(deserialized.response.length).toBe(proof.response.length);
      for (let i = 0; i < proof.response.length; i++) {
        expect(deserialized.response[i].equals(proof.response[i])).toBe(true);
      }

      expect(ni.verify(deserialized)).toBe(true);
    });

    it('serialization roundtrip (batchable)', () => {
      const x = ristretto255.randomScalar();
      const relation = createSchnorrRelation(ristretto255, x);

      const ni = new NISigmaProtocol(relation);
      const proof = ni.proveBatchable([x]);

      const bytes = ni.serializeBatchableProof(proof);
      const deserialized = ni.deserializeBatchableProof(bytes);

      expect(deserialized.commitment.length).toBe(proof.commitment.length);
      for (let i = 0; i < proof.commitment.length; i++) {
        expect(deserialized.commitment[i].equals(proof.commitment[i])).toBe(
          true
        );
      }
      expect(deserialized.response.length).toBe(proof.response.length);
      for (let i = 0; i < proof.response.length; i++) {
        expect(deserialized.response[i].equals(proof.response[i])).toBe(true);
      }

      expect(ni.verifyBatchable(deserialized)).toBe(true);
    });

    it('different session IDs produce different proofs', () => {
      const x = ristretto255.randomScalar();
      const relation = createSchnorrRelation(ristretto255, x);

      const ni1 = new NISigmaProtocol(relation, {
        sessionId: new TextEncoder().encode('session1'),
      });
      const ni2 = new NISigmaProtocol(relation, {
        sessionId: new TextEncoder().encode('session2'),
      });

      const proof1 = ni1.prove([x]);
      const proof2 = ni2.prove([x]);

      // Different session IDs should produce different challenges
      expect(proof1.challenge.equals(proof2.challenge)).toBe(false);

      // Each proof should verify with its own session
      expect(ni1.verify(proof1)).toBe(true);
      expect(ni2.verify(proof2)).toBe(true);

      // Cross-session verification should fail
      expect(ni1.verify(proof2)).toBe(false);
      expect(ni2.verify(proof1)).toBe(false);
    });

    it('DLEQ proof roundtrip', () => {
      // DLEQ: prove x such that X = x*G and Y = x*H
      const x = ristretto255.randomScalar();
      const G = ristretto255.generator();
      const h = ristretto255.randomScalar();
      const H = G.multiply(h);
      const X = G.multiply(x);
      const Y = H.multiply(x);

      const relation = new LinearRelation(ristretto255);
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

      const ni = new NISigmaProtocol(relation);
      const proof = ni.prove([x]);

      expect(ni.verify(proof)).toBe(true);
    });
  });

  describe('with P-256', () => {
    it('prove/verify roundtrip', () => {
      const x = p256.randomScalar();
      const relation = createSchnorrRelation(p256, x);

      const ni = new NISigmaProtocol(relation);
      const proof = ni.prove([x]);

      expect(ni.verify(proof)).toBe(true);
    });

    it('batchable proof roundtrip', () => {
      const x = p256.randomScalar();
      const relation = createSchnorrRelation(p256, x);

      const ni = new NISigmaProtocol(relation);
      const proof = ni.proveBatchable([x]);

      expect(ni.verifyBatchable(proof)).toBe(true);
    });
  });

  describe('error handling', () => {
    it('throws on invalid proof length (challenge-response)', () => {
      const x = ristretto255.randomScalar();
      const relation = createSchnorrRelation(ristretto255, x);

      const ni = new NISigmaProtocol(relation);

      expect(() => ni.deserializeProof(new Uint8Array(10))).toThrow(
        /Invalid proof length/
      );
    });

    it('throws on invalid proof length (batchable)', () => {
      const x = ristretto255.randomScalar();
      const relation = createSchnorrRelation(ristretto255, x);

      const ni = new NISigmaProtocol(relation);

      expect(() => ni.deserializeBatchableProof(new Uint8Array(10))).toThrow(
        /Invalid proof length/
      );
    });
  });
});

describe('Instance Labels', () => {
  it('produces deterministic labels for same relation', () => {
    const x = ristretto255.randomScalar();
    const G = ristretto255.generator();
    const X = G.multiply(x);

    // Build same relation twice
    const relation1 = new LinearRelation(ristretto255);
    const [varX1] = relation1.allocateScalars(1);
    const [varG1, varXPoint1] = relation1.allocateElements(2);
    relation1.appendEquation(varXPoint1, [[varX1, varG1]]);
    relation1.setElements([
      [varG1, G],
      [varXPoint1, X],
    ]);

    const relation2 = new LinearRelation(ristretto255);
    const [varX2] = relation2.allocateScalars(1);
    const [varG2, varXPoint2] = relation2.allocateElements(2);
    relation2.appendEquation(varXPoint2, [[varX2, varG2]]);
    relation2.setElements([
      [varG2, G],
      [varXPoint2, X],
    ]);

    expect(relation1.getInstanceLabel()).toEqual(relation2.getInstanceLabel());
  });

  it('produces different labels for different statements', () => {
    const x1 = ristretto255.randomScalar();
    const x2 = ristretto255.randomScalar();
    const G = ristretto255.generator();
    const X1 = G.multiply(x1);
    const X2 = G.multiply(x2);

    const relation1 = createSchnorrRelation(ristretto255, x1);
    const relation2 = createSchnorrRelation(ristretto255, x2);

    // Different public keys should produce different labels
    expect(relation1.getInstanceLabel()).not.toEqual(
      relation2.getInstanceLabel()
    );
  });

  it('label is order-independent for element allocation', () => {
    // DLEQ with two different allocation orders should have same label
    const x = ristretto255.randomScalar();
    const G = ristretto255.generator();
    const h = ristretto255.randomScalar();
    const H = G.multiply(h);
    const X = G.multiply(x);
    const Y = H.multiply(x);

    // Order A: allocate [G, H, X, Y] together
    const relationA = new LinearRelation(ristretto255);
    const [varXa] = relationA.allocateScalars(1);
    const [varGa, varHa, varXPointA, varYPointA] =
      relationA.allocateElements(4);
    relationA.appendEquation(varXPointA, [[varXa, varGa]]);
    relationA.appendEquation(varYPointA, [[varXa, varHa]]);
    relationA.setElements([
      [varGa, G],
      [varHa, H],
      [varXPointA, X],
      [varYPointA, Y],
    ]);
    relationA.setImage([
      [0, X],
      [1, Y],
    ]);

    // Order B: allocate [G, X], then [H, Y] separately
    const relationB = new LinearRelation(ristretto255);
    const [varXb] = relationB.allocateScalars(1);
    const [varGb, varXPointB] = relationB.allocateElements(2);
    const [varHb, varYPointB] = relationB.allocateElements(2);
    relationB.appendEquation(varXPointB, [[varXb, varGb]]);
    relationB.appendEquation(varYPointB, [[varXb, varHb]]);
    relationB.setElements([
      [varGb, G],
      [varXPointB, X],
      [varHb, H],
      [varYPointB, Y],
    ]);
    relationB.setImage([
      [0, X],
      [1, Y],
    ]);

    // Labels should be identical despite different allocation order
    expect(relationA.getInstanceLabel()).toEqual(relationB.getInstanceLabel());
  });

  it('different statements produce different proofs', () => {
    const x = ristretto255.randomScalar();
    const G = ristretto255.generator();
    const X = G.multiply(x);

    // Same witness, but different public statement (add H*0 term)
    const relation1 = createSchnorrRelation(ristretto255, x);

    // Different relation structure
    const relation2 = new LinearRelation(ristretto255);
    const [varX2, varY2] = relation2.allocateScalars(2);
    const [varG2, varH2, varXPoint2] = relation2.allocateElements(3);
    relation2.appendEquation(varXPoint2, [
      [varX2, varG2],
      [varY2, varH2],
    ]);
    const H = G.multiply(ristretto255.randomScalar());
    relation2.setElements([
      [varG2, G],
      [varH2, H],
      [varXPoint2, X],
    ]);
    relation2.setImage([[0, X]]);

    const ni1 = new NISigmaProtocol(relation1);
    const ni2 = new NISigmaProtocol(relation2);

    const proof1 = ni1.prove([x]);
    const proof2 = ni2.prove([x, ristretto255.scalarFromBigint(0n)]);

    // Different instance labels should produce different challenges
    expect(proof1.challenge.equals(proof2.challenge)).toBe(false);
  });
});
