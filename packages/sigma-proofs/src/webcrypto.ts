/**
 * P-256 scalar multiplication through WebCrypto ECDH.
 *
 * ECDH deriveBits(k, Q) returns x(k * Q), computed natively and in constant
 * time, off the main thread in most engines. Importing k as a private key
 * also yields K = k * G (exported as JWK), and with x0 = x(k * Q) and
 * x1 = x(k * (Q + G)) = x(k * Q + K), the affine addition formula
 * determines y0 without a square root:
 *
 *   (yk - y0)^2 = (x1 + x0 + xk) (xk - x0)^2,  y0^2 = x0^3 + a x0 + b
 *   => y0 = (yk^2 + x0^3 + a x0 + b - (x1 + x0 + xk)(xk - x0)^2) / (2 yk)
 *
 * The divisions share one batched inversion, and a job on G costs no
 * derivation at all. Each distinct scalar costs one import, each distinct
 * point two. Every recovered point is checked to be on the curve; any
 * failure falls back to noble for that job.
 *
 * Secret scalars always take the same path: k * Q is computed as
 * (k + 1) * Q - Q, so that k = 0 (a hidden bit, for instance) is not special.
 */

import { normalizeZ } from '@noble/curves/abstract/curve.js';
import { p256 } from '@noble/curves/nist.js';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js';
import type { Point } from './ciphersuites.js';
import { type Job, mulCt } from './effects.js';

const { Point: P256Point } = p256;
const Fp = P256Point.Fp;
const ORDER = P256Point.Fn.ORDER;
const G = P256Point.BASE;
const { a: A, b: B } = P256Point.CURVE();

/** PKCS#8 PrivateKeyInfo for P-256, ECPrivateKey { version 1, privateKey }. */
const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01,
  0x01, 0x04, 0x20,
]);
const ALG = { name: 'ECDH', namedCurve: 'P-256' };

/** Imported public keys for Q and Q + G, per point. */
const publicKeys = new WeakMap<Point, { Q: Promise<CryptoKey>; QG: Promise<CryptoKey> }>();

/** Set once an engine refuses a key format; then noble is used. */
let unsupported = false;

function noble([P, k, secret]: Job): Point {
  return secret ? mulCt(P, k, ORDER) : P.multiplyUnsafe(k);
}

function b64url(s: string | undefined): bigint {
  const bin = atob((s ?? '').replace(/-/g, '+').replace(/_/g, '/'));
  let x = 0n;
  for (let i = 0; i < bin.length; i++) x = (x << 8n) | BigInt(bin.charCodeAt(i));
  return x;
}

function rawPublic(x: bigint, y: bigint): Uint8Array<ArrayBuffer> {
  const raw = new Uint8Array(65);
  raw[0] = 4;
  raw.set(numberToBytesBE(x, 32), 1);
  raw.set(numberToBytesBE(y, 32), 33);
  return raw;
}

interface PrivateEntry {
  key: CryptoKey;
  /** K = k * G, affine. */
  x: bigint;
  y: bigint;
}

/** Runs a batch of P-256 jobs on WebCrypto. Shared scalars and points are imported once. */
export async function mulManyWebCrypto(jobs: readonly Job[]): Promise<Point[]> {
  const s = globalThis.crypto?.subtle;
  if (!s || unsupported) return jobs.map(noble);
  return mulManyWebCrypto0(s, jobs);
}

async function mulManyWebCrypto0(s: SubtleCrypto, jobs: readonly Job[]): Promise<Point[]> {
  // The scalar actually multiplied: (k + 1) for secrets; for public
  // scalars, the smaller of k and p - k, the result negated in the latter
  // case, so that k and -k share one import. undefined: a public zero (the
  // identity) or a secret k = p - 1 (negligible).
  const negated = jobs.map(([, k, secret]) => !secret && k > ORDER >> 1n);
  const scalars = jobs.map(([, k, secret], i) =>
    secret
      ? k === ORDER - 1n
        ? undefined
        : k + 1n
      : k === 0n
        ? undefined
        : negated[i]
          ? ORDER - k
          : k
  );

  // Public scalars shared by several jobs are imported once. Secret ones
  // never are: whether two secret scalars are equal (say, two zero bits)
  // must not change the work done.
  const privates = new Map<bigint, Promise<PrivateEntry>>();
  const privateKey = (k: bigint, secret: boolean): Promise<PrivateEntry> => {
    let entry = secret ? undefined : privates.get(k);
    if (!entry) {
      const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + 32);
      pkcs8.set(PKCS8_PREFIX);
      pkcs8.set(numberToBytesBE(k, 32), PKCS8_PREFIX.length);
      entry = s.importKey('pkcs8', pkcs8, ALG, true, ['deriveBits']).then(async (key) => {
        const jwk = await s.exportKey('jwk', key);
        return { key, x: b64url(jwk.x), y: b64url(jwk.y) };
      });
      pkcs8.fill(0);
      if (!secret) privates.set(k, entry);
    }
    return entry;
  };

  // Distinct points other than G not yet imported, with Q + G normalized in
  // one batch. Imports are cached per point, so long-lived points such as
  // the generators of a configuration are imported once.
  const points = [...new Set(jobs.map(([Q]) => Q))].filter(
    (Q) => !publicKeys.has(Q) && !Q.is0() && !Q.equals(G)
  );
  const plus = points.map((Q) => Q.add(G));
  const ok = plus.map((P) => !P.is0());
  const affine = normalizeZ(
    P256Point,
    points.flatMap((Q, i) => (ok[i] ? [Q, plus[i] ?? Q] : []))
  );
  let at = 0;
  points.forEach((Q, i) => {
    if (!ok[i]) return;
    const a = affine[at++]?.toAffine();
    const b = affine[at++]?.toAffine();
    if (!a || !b) return;
    publicKeys.set(Q, {
      Q: s.importKey('raw', rawPublic(a.x, a.y), ALG, false, []),
      QG: s.importKey('raw', rawPublic(b.x, b.y), ALG, false, []),
    });
  });

  const derive = async (k: CryptoKey, Q: Promise<CryptoKey>): Promise<bigint> =>
    bytesToNumberBE(new Uint8Array(await s.deriveBits({ name: 'ECDH', public: await Q }, k, 256)));

  type Raw = { x0: bigint; x1: bigint; K: PrivateEntry } | { R: Point } | undefined;
  const raw: Raw[] = await Promise.all(
    jobs.map(async ([Q, , secret], i): Promise<Raw> => {
      const k = scalars[i];
      if (k === undefined) return undefined;
      try {
        const K = await privateKey(k, secret);
        if (Q.equals(G)) return { R: P256Point.fromAffine({ x: K.x, y: K.y }) };
        const pub = publicKeys.get(Q);
        if (!pub) return undefined;
        const [x0, x1] = await Promise.all([derive(K.key, pub.Q), derive(K.key, pub.QG)]);
        return { x0, x1, K };
      } catch (e) {
        // Valid inputs never fail to import or export, so such an error
        // means the engine rejects the format: stop trying. A derivation
        // error (an identity result) only falls back for this job.
        if (
          e instanceof DOMException &&
          (e.name === 'NotSupportedError' || e.name === 'DataError')
        ) {
          unsupported = true;
        }
        return undefined;
      }
    })
  );

  const pending = raw.flatMap((r) => (r && 'x0' in r ? [r] : []));
  const inverses = Fp.invertBatch(pending.map(({ K }) => Fp.add(K.y, K.y)));
  let next = 0;
  return jobs.map((job, i) => {
    const r = raw[i];
    const [Q, , secret] = job;
    let R: Point | undefined;
    if (r && 'R' in r) R = r.R;
    else if (r) {
      const inv = inverses[next++] ?? 0n;
      const { x0, x1, K } = r;
      const rhs = Fp.add(Fp.add(Fp.mul(Fp.sqr(x0), x0), Fp.mul(A, x0)), B);
      const d = Fp.sub(K.x, x0);
      const y0 = Fp.mul(
        Fp.sub(Fp.add(Fp.sqr(K.y), rhs), Fp.mul(Fp.add(Fp.add(x1, x0), K.x), Fp.sqr(d))),
        inv
      );
      // Degenerate inputs (x0 = xk) or a misbehaving engine fail this check.
      if (d !== 0n && Fp.sqr(y0) === rhs) R = P256Point.fromAffine({ x: x0, y: y0 });
    }
    if (!R) return noble(job);
    if (secret) return R.subtract(Q);
    return negated[i] ? R.negate() : R;
  });
}
