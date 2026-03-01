/**
 * TLS Presentation Language Encoding for ACT Protocol Messages (VNEXT)
 *
 * Implements the wire format as specified in the IETF draft using TLS
 * presentation language (RFC 8446 Section 3). Fixed-size fields are
 * encoded as raw bytes, variable-length fields use a 2-byte big-endian
 * length prefix.
 *
 * Wire formats:
 * - IssuanceRequest:  K[32] || len(pok)[2] || pok[...]
 * - IssuanceResponse: A[32] || e[32] || c[32] || ctx[32] || len(pok)[2] || pok[...]
 * - SpendProof:       k[32] || s[32] || ctx[32] || A'[32] || B_bar[32] || Com[L*32] || len(pok)[2] || pok[...]
 * - Refund:           A*[32] || e*[32] || t[32] || len(pok)[2] || pok[...]
 * - CreditToken:      A[32] || e[32] || k[32] || r[32] || c[32] || ctx[32] = 192 bytes
 * - IssuanceState:    r[32] || k[32] || ctx[32] = 96 bytes
 * - SpendState:       r[32] || k[32] || m[32] || ctx[32] = 128 bytes
 * - PrivateKey:       x[32] = 32 bytes
 * - PublicKey:        W[32] = 32 bytes
 */

import type { Group, Scalar, GroupElement } from 'sigma-proofs';
import type {
  IssuanceRequest,
  IssuanceResponse,
  SpendProof,
  Refund,
  CreditToken,
  IssuanceState,
  SpendState,
  PrivateKey,
  PublicKey,
} from './types-vnext.js';

/** Error type for TLS encoding/decoding */
export class EncodingError extends Error {
  constructor(
    message: string,
    readonly code: EncodingErrorCode
  ) {
    super(message);
    this.name = 'EncodingError';
  }
}

export enum EncodingErrorCode {
  /** Input data is too short */
  TooShort = 1,
  /** Variable-length field exceeds u16 max */
  TooLong = 2,
  /** Point decompression failed or is identity */
  InvalidPoint = 3,
  /** Scalar is not canonical (>= group order) */
  InvalidScalar = 4,
  /** Trailing bytes after decode */
  TrailingData = 5,
  /** Invalid L parameter */
  InvalidL = 6,
}

// --- Low-level helpers ---

function writeElement(buf: Uint8Array[], elem: GroupElement): void {
  buf.push(elem.toBytes());
}

function writeScalar(buf: Uint8Array[], scalar: Scalar): void {
  buf.push(scalar.toBytes());
}

function writeBigint(buf: Uint8Array[], value: bigint, scalarSize: number): void {
  // Encode bigint as little-endian bytes (same as scalar encoding)
  const bytes = new Uint8Array(scalarSize);
  let v = value;
  for (let i = 0; i < scalarSize; i++) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  buf.push(bytes);
}

function writeVar(buf: Uint8Array[], data: Uint8Array): void {
  if (data.length > 0xffff) {
    throw new EncodingError('Variable field too long', EncodingErrorCode.TooLong);
  }
  const lenBuf = new Uint8Array(2);
  lenBuf[0] = (data.length >> 8) & 0xff;
  lenBuf[1] = data.length & 0xff;
  buf.push(lenBuf);
  buf.push(data);
}

function concat(parts: Uint8Array[]): Uint8Array {
  const totalLen = parts.reduce((sum, p) => sum + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function readElement(
  group: Group,
  data: Uint8Array,
  offset: { value: number }
): GroupElement {
  const size = group.elementSize;
  if (data.length < offset.value + size) {
    throw new EncodingError('Data too short for element', EncodingErrorCode.TooShort);
  }
  const bytes = data.subarray(offset.value, offset.value + size);
  offset.value += size;
  const elem = group.elementFromBytes(bytes);
  // Check for identity point (invalid in protocol)
  if (elem.equals(group.identity())) {
    throw new EncodingError('Identity point not allowed', EncodingErrorCode.InvalidPoint);
  }
  return elem;
}

function readScalar(
  group: Group,
  data: Uint8Array,
  offset: { value: number }
): Scalar {
  const size = group.scalarSize;
  if (data.length < offset.value + size) {
    throw new EncodingError('Data too short for scalar', EncodingErrorCode.TooShort);
  }
  const bytes = data.subarray(offset.value, offset.value + size);
  offset.value += size;
  try {
    return group.scalarFromBytes(bytes);
  } catch {
    throw new EncodingError('Invalid scalar encoding', EncodingErrorCode.InvalidScalar);
  }
}

function readBigint(
  data: Uint8Array,
  offset: { value: number },
  scalarSize: number
): bigint {
  if (data.length < offset.value + scalarSize) {
    throw new EncodingError('Data too short for bigint', EncodingErrorCode.TooShort);
  }
  // Decode little-endian bytes to bigint
  let value = 0n;
  for (let i = scalarSize - 1; i >= 0; i--) {
    value = (value << 8n) | BigInt(data[offset.value + i]!);
  }
  offset.value += scalarSize;
  return value;
}

function readVar(data: Uint8Array, offset: { value: number }): Uint8Array {
  if (data.length < offset.value + 2) {
    throw new EncodingError('Data too short for length prefix', EncodingErrorCode.TooShort);
  }
  const len = (data[offset.value]! << 8) | data[offset.value + 1]!;
  offset.value += 2;
  if (data.length < offset.value + len) {
    throw new EncodingError('Data too short for variable field', EncodingErrorCode.TooShort);
  }
  const result = data.slice(offset.value, offset.value + len);
  offset.value += len;
  return result;
}

function checkExact(data: Uint8Array, offset: number): void {
  if (offset !== data.length) {
    throw new EncodingError(
      `Trailing data: ${data.length - offset} bytes`,
      EncodingErrorCode.TrailingData
    );
  }
}

// --- IssuanceRequest: K[32] || len(pok)[2] || pok[...] ---

export function encodeIssuanceRequest(req: IssuanceRequest): Uint8Array {
  const buf: Uint8Array[] = [];
  writeElement(buf, req.K);
  writeVar(buf, req.pok);
  return concat(buf);
}

export function decodeIssuanceRequest(
  group: Group,
  data: Uint8Array
): IssuanceRequest {
  const offset = { value: 0 };
  const K = readElement(group, data, offset);
  const pok = readVar(data, offset);
  checkExact(data, offset.value);
  return { K, pok };
}

// --- IssuanceResponse: A[32] || e[32] || c[32] || ctx[32] || len(pok)[2] || pok[...] ---

export function encodeIssuanceResponse(
  group: Group,
  resp: IssuanceResponse & { ctx: Scalar }
): Uint8Array {
  const buf: Uint8Array[] = [];
  writeElement(buf, resp.A);
  writeScalar(buf, resp.e);
  writeBigint(buf, resp.c, group.scalarSize);
  writeScalar(buf, resp.ctx);
  writeVar(buf, resp.pok);
  return concat(buf);
}

export function decodeIssuanceResponse(
  group: Group,
  data: Uint8Array
): IssuanceResponse & { ctx: Scalar } {
  const offset = { value: 0 };
  const A = readElement(group, data, offset);
  const e = readScalar(group, data, offset);
  const c = readBigint(data, offset, group.scalarSize);
  const ctx = readScalar(group, data, offset);
  const pok = readVar(data, offset);
  checkExact(data, offset.value);
  return { A, e, c, ctx, pok };
}

// --- SpendProof: k[32] || s[32] || ctx[32] || A'[32] || B_bar[32] || Com[L*32] || len(pok)[2] || pok[...] ---

export function encodeSpendProof(group: Group, proof: SpendProof): Uint8Array {
  const buf: Uint8Array[] = [];
  writeScalar(buf, proof.k);
  writeBigint(buf, proof.s, group.scalarSize);
  writeScalar(buf, proof.ctx);
  writeElement(buf, proof.APrime);
  writeElement(buf, proof.BBar);
  for (const com of proof.Com) {
    writeElement(buf, com);
  }
  writeVar(buf, proof.pok);
  return concat(buf);
}

export function decodeSpendProof(
  group: Group,
  L: number,
  data: Uint8Array
): SpendProof {
  if (L < 1 || L > 128) {
    throw new EncodingError('L must be 1-128', EncodingErrorCode.InvalidL);
  }
  const offset = { value: 0 };
  const k = readScalar(group, data, offset);
  const s = readBigint(data, offset, group.scalarSize);
  const ctx = readScalar(group, data, offset);
  const APrime = readElement(group, data, offset);
  const BBar = readElement(group, data, offset);
  const Com: GroupElement[] = [];
  for (let i = 0; i < L; i++) {
    Com.push(readElement(group, data, offset));
  }
  const pok = readVar(data, offset);
  checkExact(data, offset.value);
  return { k, s, ctx, APrime, BBar, Com, pok };
}

// --- Refund: A*[32] || e*[32] || t[32] || len(pok)[2] || pok[...] ---

export function encodeRefund(group: Group, refund: Refund): Uint8Array {
  const buf: Uint8Array[] = [];
  writeElement(buf, refund.AStar);
  writeScalar(buf, refund.eStar);
  writeBigint(buf, refund.t, group.scalarSize);
  writeVar(buf, refund.pok);
  return concat(buf);
}

export function decodeRefund(group: Group, data: Uint8Array): Refund {
  const offset = { value: 0 };
  const AStar = readElement(group, data, offset);
  const eStar = readScalar(group, data, offset);
  const t = readBigint(data, offset, group.scalarSize);
  const pok = readVar(data, offset);
  checkExact(data, offset.value);
  return { AStar, eStar, t, pok };
}

// --- CreditToken: A[32] || e[32] || k[32] || r[32] || c[32] || ctx[32] = 192 bytes ---

export function encodeCreditToken(group: Group, token: CreditToken): Uint8Array {
  const buf: Uint8Array[] = [];
  writeElement(buf, token.A);
  writeScalar(buf, token.e);
  writeScalar(buf, token.k);
  writeScalar(buf, token.r);
  writeBigint(buf, token.c, group.scalarSize);
  writeScalar(buf, token.ctx);
  return concat(buf);
}

export function decodeCreditToken(group: Group, data: Uint8Array): CreditToken {
  const offset = { value: 0 };
  const A = readElement(group, data, offset);
  const e = readScalar(group, data, offset);
  const k = readScalar(group, data, offset);
  const r = readScalar(group, data, offset);
  const c = readBigint(data, offset, group.scalarSize);
  const ctx = readScalar(group, data, offset);
  checkExact(data, offset.value);
  return { A, e, k, r, c, ctx };
}

// --- IssuanceState: r[32] || k[32] || ctx[32] = 96 bytes ---

export function encodeIssuanceState(state: IssuanceState): Uint8Array {
  const buf: Uint8Array[] = [];
  writeScalar(buf, state.r);
  writeScalar(buf, state.k);
  writeScalar(buf, state.ctx);
  return concat(buf);
}

export function decodeIssuanceState(group: Group, data: Uint8Array): IssuanceState {
  const offset = { value: 0 };
  const r = readScalar(group, data, offset);
  const k = readScalar(group, data, offset);
  const ctx = readScalar(group, data, offset);
  checkExact(data, offset.value);
  return { r, k, ctx };
}

// --- SpendState: r[32] || k[32] || m[32] || ctx[32] = 128 bytes ---

export function encodeSpendState(group: Group, state: SpendState): Uint8Array {
  const buf: Uint8Array[] = [];
  writeScalar(buf, state.rStar);
  writeScalar(buf, state.kStar);
  writeBigint(buf, state.m, group.scalarSize);
  writeScalar(buf, state.ctx);
  return concat(buf);
}

export function decodeSpendState(group: Group, data: Uint8Array): SpendState {
  const offset = { value: 0 };
  const rStar = readScalar(group, data, offset);
  const kStar = readScalar(group, data, offset);
  const m = readBigint(data, offset, group.scalarSize);
  const ctx = readScalar(group, data, offset);
  checkExact(data, offset.value);
  return { rStar, kStar, m, ctx };
}

// --- PrivateKey: x[32] = 32 bytes ---

export function encodePrivateKey(sk: PrivateKey): Uint8Array {
  return sk.x.toBytes();
}

export function decodePrivateKey(group: Group, data: Uint8Array): PrivateKey {
  const offset = { value: 0 };
  const x = readScalar(group, data, offset);
  checkExact(data, offset.value);
  return { x };
}

// --- PublicKey: W[32] = 32 bytes ---

export function encodePublicKey(pk: PublicKey): Uint8Array {
  return pk.W.toBytes();
}

export function decodePublicKey(group: Group, data: Uint8Array): PublicKey {
  const offset = { value: 0 };
  const W = readElement(group, data, offset);
  checkExact(data, offset.value);
  return { W };
}
