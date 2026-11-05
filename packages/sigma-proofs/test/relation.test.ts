import { describe, expect, it, vi } from 'vitest';
import {
  BLS12381,
  deriveSessionId,
  deserializeScalar,
  type Job,
  LinearRelation,
  P256,
  proveBatchable,
  proveCompact,
  randomNonces,
  serializeScalar,
  verifyBatchable,
  verifyCompact,
} from '../src/index.ts';
import { mulManyWebCrypto } from '../src/webcrypto.ts';

describe.each([P256, BLS12381])('$id', (suite) => {
  // DLEQ: X = x * G, Y = x * H
  const [x = 1n, h = 1n] = randomNonces(suite, 2);
  const H = suite.Point.BASE.multiply(h);
  const build = (Y = H.multiply(x)) => {
    const rel = new LinearRelation(suite);
    const iH = rel.addElements(H, suite.Point.BASE.multiply(x), Y);
    rel.addEquation([[iH + 1, 1n]], [[0, 0, 1n]]);
    rel.addEquation([[iH + 2, 1n]], [[0, iH, 1n]]);
    return rel;
  };
  const sid = deriveSessionId(`test-CMPT-with-${suite.id}`);

  it('roundtrips serialization', () => {
    const rel = build();
    expect(LinearRelation.deserialize(suite, rel.serialize()).serialize()).toEqual(rel.serialize());
  });

  it.each([
    ['compact', proveCompact, verifyCompact],
    ['batchable', proveBatchable, verifyBatchable],
  ] as const)('%s proofs verify and bind the statement and session', async (_, prove, verify) => {
    const proof = await prove(sid, build(), [x]);
    expect(await verify(sid, build(), proof)).toBe(true);
    expect(await verify(deriveSessionId('other'), build(), proof)).toBe(false);
    expect(await verify(sid, build(H.multiply(x + 1n)), proof)).toBe(false);
    const flipped = proof.slice();
    flipped.set([(flipped.at(-1) ?? 0) ^ 1], flipped.length - 1);
    expect(await verify(sid, build(), flipped)).toBe(false);
  });

  it('does not reuse transcript bytes after changing a relation element', async () => {
    const rel = new LinearRelation(suite);
    rel.addElements(suite.Point.BASE.multiply(7n));
    rel.addEquation([[1, 1n]], [[0, 0, 1n]]);
    const proof = await proveCompact(sid, rel, [7n]);
    const c = deserializeScalar(suite, proof.subarray(0, suite.Ns));
    const z = deserializeScalar(suite, proof.subarray(suite.Ns));
    rel.elements[1] = suite.Point.BASE.multiply(8n);
    proof.set(serializeScalar(suite, (z + c) % suite.order), suite.Ns);
    expect(await verifyCompact(sid, rel, proof)).toBe(false);
    const fresh = LinearRelation.deserialize(suite, rel.serialize());
    expect(await verifyCompact(sid, fresh, proof)).toBe(false);
  });

  it('does not expose mutable transcript storage', async () => {
    const rel = build();
    rel.serialize().fill(0);
    const proof = await proveCompact(sid, rel, [x]);
    expect(await verifyCompact(sid, build(), proof)).toBe(true);
  });

  it('serializes direct equation changes', () => {
    const rel = build();
    rel.serialize();
    rel.equations.reverse();
    const fresh = build();
    fresh.equations.reverse();
    expect(rel.serialize()).toEqual(fresh.serialize());
  });

  for (const [name, prove, verify] of [
    ['compact', proveCompact, verifyCompact],
    ['batchable', proveBatchable, verifyBatchable],
  ] satisfies [string, typeof proveCompact, typeof verifyCompact][]) {
    it(`${name} snapshots prover inputs before awaiting multiplication`, async () => {
      const rel = build();
      const witness = [x];
      const nonces = randomNonces(suite, 1);
      const session = sid.slice();
      const pending = prove(session, rel, witness, nonces);
      rel.elements[2] = suite.Point.BASE;
      rel.equations.length = 0;
      witness[0] = 0n;
      nonces[0] = 0n;
      session.fill(0);
      expect(await verify(sid, build(), await pending)).toBe(true);
    });

    it(`${name} snapshots verifier inputs before awaiting multiplication`, async () => {
      const proof = await prove(sid, build(), [x]);
      const rel = build();
      const session = sid.slice();
      const pending = verify(session, rel, proof);
      rel.elements[2] = suite.Point.BASE;
      rel.equations.length = 0;
      session.fill(0);
      proof.fill(0);
      expect(await pending).toBe(true);
    });
  }

  it('rejects invalid instances', () => {
    const rel = new LinearRelation(suite);
    expect(() => rel.validate()).toThrow(/no equations/);
    rel.addElements(H);
    rel.addEquation([[1, 1n]], [[1, 0, 1n]]); // scalar 0 unused
    expect(() => rel.validate()).toThrow(/unused scalar/);
  });

  it('rejects a serialized sparse scalar index before allocating', async () => {
    const rel = new LinearRelation(suite);
    rel.addEquation([[0, 1n]], [[0xffffffff, 0, 1n]]);
    const parsed = LinearRelation.deserialize(suite, rel.serialize());
    const proof = new Uint8Array();
    const Native = Uint8Array;
    // Fail safely if allocation ordering regresses, rather than requesting 4 GiB.
    vi.stubGlobal(
      'Uint8Array',
      new Proxy(Native, {
        construct(target, args) {
          if (typeof args[0] === 'number' && args[0] > 1024) {
            throw new Error('oversized validation allocation');
          }
          return Reflect.construct(target, args);
        },
      })
    );
    try {
      expect(() => parsed.validate()).toThrow(/unused scalar/);
      expect(await verifyCompact(sid, parsed, proof)).toBe(false);
      expect(await verifyBatchable(sid, parsed, proof)).toBe(false);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it.each([-1, 0.5, NaN, Infinity, 0x100000000])('rejects invalid scalar index %s', (s) => {
    const rel = new LinearRelation(suite);
    rel.addEquation([[0, 1n]], [[s, 0, 1n]]);
    expect(() => rel.validate()).toThrow(/index out of range/);
  });
});

describe('WebCrypto batch multiplication', () => {
  it('matches noble, including edge scalars and shared keys', async () => {
    const Q = P256.Point.BASE.multiply(12345n);
    const R = P256.Point.BASE.multiply(67890n);
    const [k = 1n] = randomNonces(P256, 1);
    const n = P256.order;
    const jobs: Job[] = [
      [Q, k, true],
      [R, k, false], // same scalar, other point
      [Q, k, false], // same scalar and point
      [Q, 0n, true],
      [Q, 1n, true],
      [Q, n - 1n, true],
      [Q, n - 2n, false], // (k + 1) * Q = -Q
      [Q, (n + 1n) / 2n, true],
    ];
    const got = await mulManyWebCrypto(jobs);
    jobs.forEach(([P, s], i) => {
      expect(got?.[i]?.equals(P.multiplyUnsafe(s)), `job ${i}`).toBe(true);
    });
  });
});
