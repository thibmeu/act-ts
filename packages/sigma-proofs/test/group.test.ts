/**
 * Tests for Group, Scalar, and GroupElement interfaces
 */
import { describe, it, expect } from 'vitest';
import { ristretto255, p256, LinearRelation } from '../src/index.js';
import type { Group } from '../src/group.js';

function testGroup(group: Group, name: string) {
  describe(name, () => {
    describe('Scalar arithmetic', () => {
      it('add is commutative: a + b = b + a', () => {
        const a = group.randomScalar();
        const b = group.randomScalar();
        expect(a.add(b).equals(b.add(a))).toBe(true);
      });

      it('sub is inverse of add: (a + b) - b = a', () => {
        const a = group.randomScalar();
        const b = group.randomScalar();
        expect(a.add(b).sub(b).equals(a)).toBe(true);
      });

      it('mul is commutative: a * b = b * a', () => {
        const a = group.randomScalar();
        const b = group.randomScalar();
        expect(a.mul(b).equals(b.mul(a))).toBe(true);
      });

      it('neg: a + (-a) = 0', () => {
        const a = group.randomScalar();
        const zero = group.scalarFromBigint(0n);
        expect(a.add(a.neg()).equals(zero)).toBe(true);
      });

      it('inv: a * a^{-1} = 1', () => {
        const a = group.randomScalar();
        const one = group.scalarFromBigint(1n);
        expect(a.mul(a.inv()).equals(one)).toBe(true);
      });

      it('inv throws on zero', () => {
        const zero = group.scalarFromBigint(0n);
        expect(() => zero.inv()).toThrow('Cannot invert zero');
      });

      it('isZero returns true only for zero', () => {
        const zero = group.scalarFromBigint(0n);
        const one = group.scalarFromBigint(1n);
        const random = group.randomScalar();
        expect(zero.isZero()).toBe(true);
        expect(one.isZero()).toBe(false);
        expect(random.isZero()).toBe(false);
      });

      it('serialization round-trip', () => {
        const a = group.randomScalar();
        const bytes = a.toBytes();
        const restored = group.scalarFromBytes(bytes);
        expect(restored.equals(a)).toBe(true);
      });
    });

    describe('GroupElement operations', () => {
      it('identity is additive identity: P + I = P', () => {
        const P = group.generator().multiply(group.randomScalar());
        const I = group.identity();
        expect(P.add(I).equals(P)).toBe(true);
      });

      it('scalar multiplication: (a * b) * G = a * (b * G)', () => {
        const a = group.randomScalar();
        const b = group.randomScalar();
        const G = group.generator();
        const lhs = G.multiply(a.mul(b));
        const rhs = G.multiply(b).multiply(a);
        expect(lhs.equals(rhs)).toBe(true);
      });

      it('serialization round-trip', () => {
        const P = group.generator().multiply(group.randomScalar());
        const bytes = P.toBytes();
        const restored = group.elementFromBytes(bytes);
        expect(restored.equals(P)).toBe(true);
      });
    });

    describe('Type safety', () => {
      it('rejects mixing scalars from different groups', () => {
        // Only test if we have both groups
        if (name === 'ristretto255') {
          const r255Scalar = ristretto255.randomScalar();
          const p256Scalar = p256.randomScalar();
          expect(() => r255Scalar.add(p256Scalar)).toThrow('Cannot mix scalars');
        }
      });

      it('rejects mixing elements from different groups', () => {
        if (name === 'ristretto255') {
          const r255Element = ristretto255.generator();
          const p256Element = p256.generator();
          expect(() => r255Element.add(p256Element)).toThrow('Cannot mix elements');
        }
      });

      it('rejects mixing scalar/element from different groups', () => {
        if (name === 'ristretto255') {
          const r255Element = ristretto255.generator();
          const p256Scalar = p256.randomScalar();
          expect(() => r255Element.multiply(p256Scalar)).toThrow('Cannot mix');
        }
      });
    });

    describe('Hash-to-curve', () => {
      it('hashToElement produces valid group element', () => {
        const data = new Uint8Array([1, 2, 3, 4]);
        const element = group.hashToElement(data);
        // Should be serializable and deserializable
        const bytes = element.toBytes();
        const restored = group.elementFromBytes(bytes);
        expect(restored.equals(element)).toBe(true);
      });

      it('hashToElement is deterministic', () => {
        const data = new Uint8Array([1, 2, 3, 4]);
        const e1 = group.hashToElement(data);
        const e2 = group.hashToElement(data);
        expect(e1.equals(e2)).toBe(true);
      });

      it('hashToElement with different data produces different elements', () => {
        const data1 = new Uint8Array([1, 2, 3, 4]);
        const data2 = new Uint8Array([5, 6, 7, 8]);
        const e1 = group.hashToElement(data1);
        const e2 = group.hashToElement(data2);
        expect(e1.equals(e2)).toBe(false);
      });

      it('hashToScalar produces valid scalar', () => {
        const data = new Uint8Array([1, 2, 3, 4]);
        const scalar = group.hashToScalar(data);
        // Should be serializable and deserializable
        const bytes = scalar.toBytes();
        const restored = group.scalarFromBytes(bytes);
        expect(restored.equals(scalar)).toBe(true);
      });

      it('hashToScalar is deterministic', () => {
        const data = new Uint8Array([1, 2, 3, 4]);
        const s1 = group.hashToScalar(data);
        const s2 = group.hashToScalar(data);
        expect(s1.equals(s2)).toBe(true);
      });

      it('hashToScalar with different data produces different scalars', () => {
        const data1 = new Uint8Array([1, 2, 3, 4]);
        const data2 = new Uint8Array([5, 6, 7, 8]);
        const s1 = group.hashToScalar(data1);
        const s2 = group.hashToScalar(data2);
        expect(s1.equals(s2)).toBe(false);
      });

      it('hashToElement with custom DST', () => {
        const data = new Uint8Array([1, 2, 3, 4]);
        const dst1 = new TextEncoder().encode('DST1');
        const dst2 = new TextEncoder().encode('DST2');
        const e1 = group.hashToElement(data, dst1);
        const e2 = group.hashToElement(data, dst2);
        // Different DSTs should produce different elements
        expect(e1.equals(e2)).toBe(false);
      });
    });

    describe('Allocation limits', () => {
      it('rejects excessive scalar allocation', () => {
        const relation = new LinearRelation(group);
        expect(() => relation.allocateScalars(2000)).toThrow('exceed limit');
      });

      it('rejects excessive element allocation', () => {
        const relation = new LinearRelation(group);
        expect(() => relation.allocateElements(2000)).toThrow('exceed limit');
      });

      it('rejects negative allocation', () => {
        const relation = new LinearRelation(group);
        expect(() => relation.allocateScalars(-1)).toThrow('negative');
        expect(() => relation.allocateElements(-1)).toThrow('negative');
      });
    });

    describe('Bounds checking', () => {
      it('rejects negative index in setElements', () => {
        const relation = new LinearRelation(group);
        relation.allocateElements(2);
        expect(() => relation.setElements([[-1, group.generator()]])).toThrow('out of bounds');
      });

      it('rejects negative index in setImage', () => {
        const relation = new LinearRelation(group);
        relation.allocateScalars(1);
        relation.allocateElements(2);
        relation.appendEquation(1, [[0, 0]]);
        expect(() => relation.setImage([[-1, group.generator()]])).toThrow('out of bounds');
      });
    });
  });
}

describe('Group implementations', () => {
  testGroup(ristretto255, 'ristretto255');
  testGroup(p256, 'P-256');
});
