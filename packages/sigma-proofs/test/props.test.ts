/**
 * Property tests: codecs, relation encoding, proofs, and the WebCrypto
 * backend, on both ciphersuites. Points come from a pool built once, since
 * a scalar multiplication dominates the cost of generating one.
 */

import { fc, it } from '@fast-check/vitest';
import { describe, expect, vi } from 'vitest';
import {
  BLS12381,
  type Ciphersuite,
  deriveSessionId,
  deserializeElement,
  deserializeScalar,
  type ImageTerm,
  LinearRelation,
  P256,
  type Point,
  proveBatchable,
  proveCompact,
  SigmaError,
  serializeElement,
  serializeScalar,
  type Term,
  verifyBatchable,
  verifyCompact,
} from '../src/index.ts';
import { mulManyWebCrypto } from '../src/webcrypto.ts';

/** Run count for properties that prove or multiply; they cost milliseconds each. */
const CRYPTO = { numRuns: 15 };

/** The suite without its native backend, so that noble runs every multiplication. */
const withoutNative = ({ mulMany: _native, ...suite }: Ciphersuite): Ciphersuite => suite;
vi.setConfig({ testTimeout: 60_000 });

/** Bytes mixing fast-check's small values, uniform values, and constant fills. */
const bytesArb = (minLength: number, maxLength: number): fc.Arbitrary<Uint8Array> =>
  fc.oneof(
    fc.uint8Array({ minLength, maxLength }),
    fc
      .integer({ min: minLength, max: maxLength })
      .chain((n) => fc.uint8Array({ minLength: n, maxLength: n, min: 0, max: 255 })),
    fc
      .tuple(
        fc.integer({ min: minLength, max: maxLength }),
        fc.constantFrom(0x00, 0x01, 0x02, 0x03, 0x7f, 0x80, 0xff)
      )
      .map(([n, b]) => new Uint8Array(n).fill(b))
  );

/** Scalars: uniform, plus the boundaries of [0, p). */
const scalarArb = (s: Ciphersuite): fc.Arbitrary<bigint> =>
  fc.oneof(
    fc.bigInt({ min: 0n, max: s.order - 1n }),
    fc.constantFrom(0n, 1n, 2n, s.order >> 1n, (s.order >> 1n) + 1n, s.order - 2n, s.order - 1n)
  );

/** Nonzero scalars, for coefficients and witnesses. */
const nonzeroArb = (s: Ciphersuite): fc.Arbitrary<bigint> => scalarArb(s).filter((k) => k !== 0n);

const pools = new Map<Ciphersuite, Point[]>();
const pool = (s: Ciphersuite): Point[] => {
  let points = pools.get(s);
  if (!points) {
    const G = s.Point.BASE;
    points = [
      G,
      G.double(),
      ...[3n, 0xdeadbeefn, s.order - 1n, s.order >> 1n].map((k) => G.multiply(k)),
    ];
    pools.set(s, points);
  }
  return points;
};
const pointArb = (s: Ciphersuite): fc.Arbitrary<Point> => fc.constantFrom(...pool(s));

/**
 * A valid instance with its witness: random terms over pooled elements, every
 * scalar used, and each image the evaluation of its terms, registered as an
 * element of its own.
 */
const relationArb = (s: Ciphersuite) =>
  fc
    .record({
      witness: fc.array(nonzeroArb(s), { minLength: 1, maxLength: 4 }),
      bases: fc.array(pointArb(s), { minLength: 1, maxLength: 3 }),
      equations: fc.array(
        fc.array(fc.tuple(fc.nat(), fc.nat(), nonzeroArb(s)), { minLength: 1, maxLength: 3 }),
        { minLength: 1, maxLength: 4 }
      ),
    })
    .map(({ witness, bases, equations }) => {
      const rel = new LinearRelation(s);
      const first = rel.addElements(...bases);
      const nb = bases.length + 1; // element 0 is the generator
      const used = new Set<number>();
      const eqs: Term[][] = equations.map((terms) =>
        terms.map(([si, ei, c]): Term => {
          const scalar = si % witness.length;
          used.add(scalar);
          return [scalar, ei % nb === 0 ? 0 : first + (ei % nb) - 1, c];
        })
      );
      witness.forEach((_, i) => {
        if (!used.has(i)) eqs[0]?.push([i, 0, 1n]);
      });
      for (const terms of eqs) {
        const image = terms.reduce(
          (acc, [si, ei, c]) =>
            acc.add(
              (rel.elements[ei] ?? s.Point.BASE).multiplyUnsafe((c * (witness[si] ?? 1n)) % s.order)
            ),
          s.Point.ZERO
        );
        const imageTerm: ImageTerm = [rel.addElements(image), 1n];
        rel.addEquation([imageTerm], terms);
      }
      return { rel, witness };
    })
    .filter(({ rel }) => {
      try {
        rel.validate(); // an identity image or column has negligible probability
        return true;
      } catch {
        return false;
      }
    });

const flip = (b: Uint8Array, at: number, bit: number): Uint8Array => {
  const out = b.slice();
  out[at % out.length] = (out[at % out.length] ?? 0) ^ (1 << bit);
  return out;
};

/** `f` returns, or throws a SigmaError; nothing else escapes. */
const failsClosed = (f: () => unknown): void => {
  try {
    f();
  } catch (e) {
    expect(e).toBeInstanceOf(SigmaError);
  }
};

describe.each([P256, BLS12381])('$id', (s) => {
  describe('codecs (Section 8)', () => {
    it.prop([scalarArb(s)])('scalars round-trip', (k) => {
      expect(deserializeScalar(s, serializeScalar(s, k))).toBe(k);
    });

    it.prop([bytesArb(s.Ns, s.Ns)])(
      'a scalar decodes exactly when it is below p, canonically',
      (b) => {
        const value = BigInt(`0x${Buffer.from(b).toString('hex')}`);
        if (value < s.order) expect(serializeScalar(s, deserializeScalar(s, b))).toEqual(b);
        else expect(() => deserializeScalar(s, b)).toThrow(SigmaError);
      }
    );

    it.prop([bytesArb(s.Ne, s.Ne)])(
      'an element decodes only to its canonical encoding, never the identity',
      (b) => {
        failsClosed(() => {
          const P = deserializeElement(s, b);
          expect(P.is0()).toBe(false);
          expect(serializeElement(s, P)).toEqual(b);
        });
      }
    );
  });

  describe('relation encoding (Section 3.6)', () => {
    it.prop([relationArb(s)], CRYPTO)('SerializeLinearRelation round-trips', ({ rel }) => {
      expect(LinearRelation.deserialize(s, rel.serialize()).serialize()).toEqual(rel.serialize());
    });

    it.prop([bytesArb(0, 512)])('arbitrary bytes deserialize and validate fail closed', (b) => {
      failsClosed(() => LinearRelation.deserialize(s, b).validate());
    });

    it.prop([relationArb(s), fc.nat(), fc.integer({ min: 0, max: 7 })], CRYPTO)(
      'a mutated encoding fails closed',
      ({ rel }, at, bit) => {
        failsClosed(() => LinearRelation.deserialize(s, flip(rel.serialize(), at, bit)).validate());
      }
    );
  });

  describe('proofs (Section 5)', () => {
    const sid = deriveSessionId(`props-CMPT-with-${s.id}`);

    it.prop([relationArb(s)], CRYPTO)(
      'honest compact and batchable proofs verify',
      async ({ rel, witness }) => {
        expect(await verifyCompact(sid, rel, await proveCompact(sid, rel, witness))).toBe(true);
        expect(await verifyBatchable(sid, rel, await proveBatchable(sid, rel, witness))).toBe(true);
      }
    );

    it.prop([relationArb(s), fc.nat(), fc.integer({ min: 0, max: 7 })], CRYPTO)(
      'any single-bit flip of a proof is rejected',
      async ({ rel, witness }, at, bit) => {
        const compact = flip(await proveCompact(sid, rel, witness), at, bit);
        const batchable = flip(await proveBatchable(sid, rel, witness), at, bit);
        expect(await verifyCompact(sid, rel, compact)).toBe(false);
        expect(await verifyBatchable(sid, rel, batchable)).toBe(false);
      }
    );

    it.prop([relationArb(s)], CRYPTO)(
      'a proof does not verify under another session',
      async ({ rel, witness }) => {
        const proof = await proveCompact(sid, rel, witness);
        expect(await verifyCompact(deriveSessionId('other'), rel, proof)).toBe(false);
      }
    );

    it.prop([relationArb(s), fc.array(scalarArb(s), { minLength: 4, maxLength: 4 })], CRYPTO)(
      'the native and noble backends agree, on any nonces',
      async ({ rel, witness }, nonces) => {
        // Adversarial nonces can cancel to an identity commitment; both reject it.
        const n = nonces.slice(0, witness.length);
        const outcome = (r: LinearRelation) =>
          proveCompact(sid, r, witness, n).catch((e: unknown) =>
            e instanceof SigmaError ? 'rejected' : Promise.reject(e)
          );
        const noble = LinearRelation.deserialize(withoutNative(s), rel.serialize());
        expect(await outcome(rel)).toEqual(await outcome(noble));
      }
    );
  });
});

describe('WebCrypto backend', () => {
  const jobArb = fc.tuple(pointArb(P256), scalarArb(P256), fc.boolean());

  it.prop([fc.array(jobArb, { minLength: 1, maxLength: 12 })], CRYPTO)(
    'every job equals noble, secret or public, including shared scalars and points',
    async (jobs) => {
      const got = await mulManyWebCrypto(jobs);
      for (const [i, [P, k]] of jobs.entries()) {
        expect(got?.[i]?.equals(P.multiplyUnsafe(k))).toBe(true);
      }
    }
  );
});
