/**
 * The P-256 group of EC-IHAT (draft-ladd-mole-ec-ihat-00, Sections 3.1,
 * 4.2-4.4 and 7.1), instantiated with an EC-ACT protocol context.
 */

import { expand_message_xmd } from '@noble/curves/abstract/hash-to-curve.js';
import { mod } from '@noble/curves/abstract/modular.js';
import type { WeierstrassPointCons } from '@noble/curves/abstract/weierstrass.js';
import { p256, p256_hasher } from '@noble/curves/nist.js';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import {
  deserializeElement,
  deserializeScalar,
  P256,
  type Point as SigmaPoint,
} from 'sigma-proofs';
import { ACTError } from './errors.ts';

export type Point = SigmaPoint;
export const Point: WeierstrassPointCons<bigint> = p256.Point;
/** Group order p. */
export const ORDER: bigint = Point.Fn.ORDER;
export const NS = 32;
export const NE = 33;
export const NSEED = 48;
/** Nh: the SHA-256 output length. */
const NH = 32;
/** s_in_bytes of SHA-256. */
const BLOCK = 64;

export const i2osp = (value: number | bigint, length: number): Uint8Array =>
  numberToBytesBE(value, length);

/** U16Prefixed(value). */
export function u16Prefixed(value: Uint8Array): Uint8Array {
  if (value.length > 0xffff) throw new ACTError('Value', 'byte string longer than 2^16 - 1');
  return concatBytes(i2osp(value.length, 2), value);
}

const xmd = (msg: Uint8Array, dst: Uint8Array, len: number): Uint8Array =>
  expand_message_xmd(msg, dst, len, sha256);

const dst = (label: string, ctx: Uint8Array): Uint8Array => concatBytes(utf8ToBytes(label), ctx);

/** HashToScalar(x, DST): hash_to_field with L = 48. */
export function hashToScalar(msg: Uint8Array, DST: Uint8Array): bigint {
  return mod(bytesToNumberBE(xmd(msg, DST, 48)), ORDER);
}

/** HashToGroup(x): P256_XMD:SHA-256_SSWU_RO_ under "HashToGroup-" || ctx. */
export function hashToGroup(ctx: Uint8Array, msg: Uint8Array): Point {
  return p256_hasher.hashToCurve(msg, { DST: dst('HashToGroup-', ctx) });
}

/** G.ExpandScalars(key, count) (Section 4.2). */
export function expandScalars(ctx: Uint8Array, key: Uint8Array, count: number): bigint[] {
  const DST = dst('ExpandScalars-', ctx);
  const scalars = Array.from({ length: count }, (_, i) =>
    hashToScalar(concatBytes(key, i2osp(i, 4)), DST)
  );
  // Every scalar is computed before a zero is reported.
  if (scalars.includes(0n)) throw new ACTError('Derive', 'derived scalar is zero');
  return scalars;
}

function checkSeed(rand: Uint8Array): void {
  if (rand.length !== NSEED) throw new ACTError('Value', `rand must be exactly ${NSEED} bytes`);
}

/** G.DeriveScalars(rand, info, count) (Section 4.2). */
export function deriveScalars(
  ctx: Uint8Array,
  rand: Uint8Array,
  info: string,
  count: number
): bigint[] {
  checkSeed(rand);
  const key = xmd(
    concatBytes(rand, u16Prefixed(utf8ToBytes(info))),
    dst('DeriveScalars-', ctx),
    NH
  );
  return expandScalars(ctx, key, count);
}

const padToBlock = (value: Uint8Array): Uint8Array =>
  concatBytes(value, new Uint8Array((BLOCK - (value.length % BLOCK)) % BLOCK));

/** G.DeriveNonces(secret, label, instance, rand, count) (Section 4.3). */
export function deriveNonces(
  ctx: Uint8Array,
  secret: Uint8Array,
  label: string,
  instance: Uint8Array,
  rand: Uint8Array,
  count: number
): bigint[] {
  checkSeed(rand);
  const input = concatBytes(
    padToBlock(rand),
    padToBlock(concatBytes(i2osp(secret.length, 4), secret)),
    u16Prefixed(utf8ToBytes(label)),
    i2osp(instance.length, 4),
    instance
  );
  const key = xmd(input, dst('DeriveNonces-', ctx), NH);
  input.fill(0);
  return expandScalars(ctx, key, count);
}

/** The secret scalar of G.DeriveKeyPair(seed, info) (Section 4.4). */
export function deriveKeyScalar(ctx: Uint8Array, seed: Uint8Array, info: string): bigint {
  checkSeed(seed);
  const input = concatBytes(seed, u16Prefixed(utf8ToBytes(info)));
  const DST = dst('DeriveKeyPair-', ctx);
  for (let counter = 0; counter < 256; counter++) {
    const skM = hashToScalar(concatBytes(input, i2osp(counter, 1)), DST);
    if (skM !== 0n) return skM;
  }
  throw new ACTError('Derive', 'DeriveKeyPair failed');
}

export const serializeScalar = (s: bigint): Uint8Array => i2osp(s, NS);
export const serializeElement = (p: Point): Uint8Array => p.toBytes(true);

/** DeserializeScalar, raising DeserializeError. */
export function deserializeScalarOrThrow(bytes: Uint8Array): bigint {
  try {
    return deserializeScalar(P256, bytes);
  } catch {
    throw new ACTError('Deserialize', 'invalid scalar');
  }
}

/** DeserializeElement, raising DeserializeError (rejects the identity). */
export function deserializeElementOrThrow(bytes: Uint8Array): Point {
  try {
    return deserializeElement(P256, bytes);
  } catch {
    throw new ACTError('Deserialize', 'invalid element');
  }
}

/**
 * x * P for a secret x in [0, 2^64]. noble's constant-time multiply rejects
 * zero, so compute (x + 1) * P - P, which never branches on x.
 */
export const mulSmall = (P: Point, x: bigint): Point => P.multiply(x + 1n).subtract(P);
