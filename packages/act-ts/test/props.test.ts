/**
 * Property tests: amounts (Section 4.3), encodings (Section 4.7), and the
 * protocol over random amounts. Configurations and points are built once per
 * balance width, since hash-to-curve and scalar multiplication dominate.
 */

import { fc, it } from '@fast-check/vitest';
import { describe, expect, vi } from 'vitest';
import {
  ACTError,
  type ACTErrorCode,
  createParams,
  decodeCredential,
  decodeIssuanceState,
  decodeIssueRequest,
  decodeIssueResponse,
  decodePublicKey,
  decodeRefund,
  decodeSecretKey,
  decodeSpend,
  decodeSpendState,
  encodeCredential,
  encodeIssuanceState,
  encodeIssueRequest,
  encodeIssueResponse,
  encodePublicKey,
  encodeRefund,
  encodeSecretKey,
  encodeSpend,
  encodeSpendState,
  finalizeIssue,
  finalizeRefund,
  generateKeys,
  issueRefund,
  issueRequest,
  issueResponse,
  type Params,
  type Point,
  proveSpend,
  rangeWeights,
  verifySpend,
} from '../src/index.ts';

/** Run count for properties that prove or verify; they cost milliseconds each. */
const CRYPTO = { numRuns: 15 };
vi.setConfig({ testTimeout: 60_000 });

const ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const paramsCache = new Map<number, Params>();
const params = (L: number): Params => {
  let p = paramsCache.get(L);
  if (!p) {
    p = createParams(L);
    paramsCache.set(L, p);
  }
  return p;
};
const max = (L: number): bigint => (1n << BigInt(L)) - 1n;

const G = params(8).H1; // any point; a pool keeps generation cheap
const pool: Point[] = [G, G.double(), ...[3n, 0xdeadbeefn, ORDER - 1n].map((k) => G.multiply(k))];

const LArb = fc.integer({ min: 1, max: 64 });
const scalarArb = fc.oneof(
  fc.bigInt({ min: 0n, max: ORDER - 1n }),
  fc.constantFrom(0n, 1n, ORDER >> 1n, ORDER - 1n)
);
const pointArb = fc.constantFrom(...pool);

/** An amount in [0, 2^L): uniform, plus the boundaries. */
const amountArb = (L: number): fc.Arbitrary<bigint> =>
  fc.oneof(fc.bigInt({ min: 0n, max: max(L) }), fc.constantFrom(0n, 1n, max(L) >> 1n, max(L)));

/** Bytes mixing fast-check's small values, uniform values, and constant fills. */
const bytesArb = (maxLength: number): fc.Arbitrary<Uint8Array> =>
  fc.oneof(
    fc.uint8Array({ maxLength }),
    fc.nat({ max: maxLength }).chain((n) => fc.uint8Array({ minLength: n, maxLength: n })),
    fc
      .tuple(fc.nat({ max: maxLength }), fc.constantFrom(0x00, 0x02, 0x03, 0xff))
      .map(([n, b]) => new Uint8Array(n).fill(b))
  );

/** A proof field of `n` canonical scalars. */
const pokArb = (n: number): fc.Arbitrary<Uint8Array> =>
  fc
    .array(scalarArb, { minLength: n, maxLength: n })
    .map((ks) =>
      Uint8Array.from(ks.flatMap((k) => [...Buffer.from(k.toString(16).padStart(64, '0'), 'hex')]))
    );

/** A well-formed spend message for width L, its shape fixed by s and a. */
const spendArb = fc.integer({ min: 1, max: 16 }).chain((L) =>
  fc
    .tuple(amountArb(L), amountArb(L))
    .filter(([s, a]) => s + a <= max(L))
    .chain(([s, a]) => {
      const n = s + a === 0n ? 0 : rangeWeights(params(L), max(L) - s - a).length;
      return fc.record({
        L: fc.constant(L),
        k: scalarArb,
        s: fc.constant(s),
        a: fc.constant(a),
        Aprime: pointArb,
        Bbar: pointArb,
        Kn: pointArb,
        com1: fc.array(pointArb, { minLength: n, maxLength: n }),
        comC: s + a === 0n ? pointArb : fc.constant(undefined),
        pok: pokArb(8 + (s + a === 0n ? 1 : 3 * n)), // Nw + 1; n = 0 when s + a = 2^L - 1
      });
    })
);

const code = (f: () => unknown): ACTErrorCode | undefined => {
  try {
    f();
  } catch (e) {
    if (e instanceof ACTError) return e.code;
    throw e; // anything else escapes: the decoder did not fail closed
  }
  return undefined;
};

describe('amounts (Section 4.3)', () => {
  it.prop([LArb.chain((L) => fc.tuple(fc.constant(L), amountArb(L)))])(
    'RangeWeights(m): positive weights summing to m, one per bit of m',
    ([L, m]) => {
      const w = rangeWeights(params(L), m);
      expect(w.every((x) => x > 0n)).toBe(true);
      expect(w.reduce((a, b) => a + b, 0n)).toBe(m);
      expect(w.length).toBe(m === 0n ? 0 : m.toString(2).length);
    }
  );

  it.prop([LArb, fc.bigInt({ min: 0n, max: 1n << 70n })])(
    'amounts at or above 2^L are rejected',
    (L, m) => {
      expect(code(() => rangeWeights(params(L), max(L) + 1n + m))).toBe('Amount');
    }
  );
});

describe('encodings (Section 4.7)', () => {
  /** A codec under test: valid encodings, and decode-then-encode. */
  const codec = <T>(
    name: string,
    arb: fc.Arbitrary<T>,
    encode: (x: T) => Uint8Array,
    decode: (b: Uint8Array) => T
  ) => ({ name, encodings: arb.map(encode), reencode: (b: Uint8Array) => encode(decode(b)) });

  const p16 = params(16);
  const codecs = [
    codec(
      'IssueRequest',
      fc.record({ K: pointArb, pok: pokArb(3) }),
      encodeIssueRequest,
      decodeIssueRequest
    ),
    codec(
      'IssueResponse',
      fc.record({ A: pointArb, e: scalarArb, c: amountArb(16), pok: pokArb(2) }),
      encodeIssueResponse,
      (b) => decodeIssueResponse(p16, b)
    ),
    codec(
      'Refund',
      fc.record({ A: pointArb, e: scalarArb, t: amountArb(16), pok: pokArb(2) }),
      encodeRefund,
      (b) => decodeRefund(p16, b)
    ),
    codec(
      'Credential',
      fc.record({ k: scalarArb, c: amountArb(16), r: scalarArb, A: pointArb, e: scalarArb }),
      encodeCredential,
      (b) => decodeCredential(p16, b)
    ),
    codec(
      'IssuanceState',
      fc.record({ k: scalarArb, r: scalarArb, K: pointArb }),
      encodeIssuanceState,
      decodeIssuanceState
    ),
    codec(
      'SpendState',
      fc.record({
        kstar: scalarArb,
        rStar: scalarArb,
        v1: amountArb(16),
        s: amountArb(16),
        a: amountArb(16),
        Kprime: pointArb,
      }),
      encodeSpendState,
      (b) => decodeSpendState(p16, b)
    ),
    codec('PublicKey', pointArb, encodePublicKey, decodePublicKey),
    codec(
      'SecretKey',
      scalarArb.filter((k) => k !== 0n).map((skM) => ({ skM, pkM: G })),
      encodeSecretKey,
      decodeSecretKey
    ),
  ];

  for (const { name, encodings, reencode } of codecs) {
    it.prop([encodings])(`${name}: decoding then encoding returns the same bytes`, (b) => {
      expect(reencode(b)).toEqual(b);
    });

    it.prop([bytesArb(160)])(`${name}: arbitrary bytes are rejected or decode canonically`, (b) => {
      code(() => expect(reencode(b)).toEqual(b));
    });
  }

  it.prop([spendArb])('Spend: decode(encode(x)) re-encodes to the same bytes', (x) => {
    const bytes = encodeSpend(x);
    expect(encodeSpend(decodeSpend(params(x.L), bytes))).toEqual(bytes);
  });

  it.prop([spendArb, fc.nat(), fc.integer({ min: 0, max: 7 })])(
    'Spend: any single-bit flip is rejected or decodes canonically',
    (x, at, bit) => {
      const bytes = encodeSpend(x);
      bytes[at % bytes.length] = (bytes[at % bytes.length] ?? 0) ^ (1 << bit);
      code(() => expect(encodeSpend(decodeSpend(params(x.L), bytes))).toEqual(bytes));
    }
  );

  it.prop([spendArb, fc.nat(), fc.integer({ min: 1, max: 64 })])(
    'Spend: truncation or extension is rejected',
    (x, cut, extra) => {
      const bytes = encodeSpend(x);
      expect(
        code(() => decodeSpend(params(x.L), bytes.subarray(0, cut % bytes.length)))
      ).toBeDefined();
      expect(
        code(() => decodeSpend(params(x.L), new Uint8Array([...bytes, ...new Uint8Array(extra)])))
      ).toBeDefined();
    }
  );

  it.prop([spendArb, fc.bigInt({ min: 1n, max: 1n << 63n }), fc.boolean()])(
    'Spend: s or a beyond 2^L - 1 - (other) is an AmountError, before the shape',
    (x, excess, onS) => {
      const s = onS ? max(x.L) - x.a + excess : x.s;
      const a = onS ? x.a : max(x.L) - x.s + excess;
      expect(code(() => decodeSpend(params(x.L), encodeSpend({ ...x, s, a })))).toBe('Amount');
    }
  );
});

describe('protocol (Section 4.6)', async () => {
  const ctxCred = new TextEncoder().encode('props');
  const ctxSpend = new TextEncoder().encode('challenge');
  const keys = await generateKeys(params(8));

  /** (L, c, s, a, t) with s <= c, c + a < 2^L, and t <= s + a. */
  const flowArb = fc.integer({ min: 1, max: 8 }).chain((L) =>
    amountArb(L).chain((c) =>
      fc
        .tuple(fc.bigInt({ min: 0n, max: c }), fc.bigInt({ min: 0n, max: max(L) - c }))
        .chain(([s, a]) =>
          fc.record({
            L: fc.constant(L),
            c: fc.constant(c),
            s: fc.constant(s),
            a: fc.constant(a),
            t: fc.bigInt({ min: 0n, max: s + a }),
          })
        )
    )
  );

  const issue = async (p: Params, c: bigint) => {
    const { state, request } = await issueRequest(p);
    const response = await issueResponse(p, keys.skM, ctxCred, c, request);
    return finalizeIssue(p, keys.pkM, ctxCred, state, response);
  };

  it.prop([flowArb], CRYPTO)(
    'a spend and refund leave exactly c - s + t',
    async ({ L, c, s, a, t }) => {
      const p = params(L);
      const { state, proof } = await proveSpend(p, await issue(p, c), ctxCred, s, a, ctxSpend);
      const wire = decodeSpend(p, encodeSpend(proof));
      const verified = await verifySpend(p, keys.skM, ctxCred, ctxSpend, wire);
      const next = await finalizeRefund(
        p,
        keys.pkM,
        ctxCred,
        state,
        await issueRefund(verified, t)
      );
      expect(next.c).toBe(c - s + t);
    }
  );

  it.prop([flowArb, fc.nat(), fc.integer({ min: 0, max: 7 })], CRYPTO)(
    'any single-bit flip of a spend message fails with an ACTError, never verifies',
    async ({ L, c, s, a }, at, bit) => {
      const p = params(L);
      const bytes = encodeSpend(
        (await proveSpend(p, await issue(p, c), ctxCred, s, a, ctxSpend)).proof
      );
      bytes[at % bytes.length] = (bytes[at % bytes.length] ?? 0) ^ (1 << bit);
      const outcome = Promise.resolve().then(() =>
        verifySpend(p, keys.skM, ctxCred, ctxSpend, decodeSpend(p, bytes))
      );
      await expect(outcome).rejects.toBeInstanceOf(ACTError);
    }
  );

  it.prop([flowArb.filter(({ L, c }) => c < max(L))], CRYPTO)(
    'the Client refuses to spend more than its balance, and the Credential stays spendable',
    async ({ L, c, a }) => {
      const p = params(L);
      const credential = await issue(p, c);
      const over = proveSpend(p, credential, ctxCred, c + 1n, 0n, ctxSpend);
      await expect(over).rejects.toMatchObject({ code: 'Amount' });
      await expect(proveSpend(p, credential, ctxCred, 0n, a, ctxSpend)).resolves.toBeDefined();
    }
  );
});
