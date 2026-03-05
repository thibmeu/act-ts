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
} from './types.js';

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

// --- Low-level helpers using DataView ---

/**
 * Writer helper that collects byte chunks for efficient concatenation.
 */
class Writer {
  private parts: Uint8Array[] = [];

  writeBytes(bytes: Uint8Array): void {
    this.parts.push(bytes);
  }

  writeElement(elem: GroupElement): void {
    this.parts.push(elem.toBytes());
  }

  writeScalar(scalar: Scalar): void {
    this.parts.push(scalar.toBytes());
  }

  /** Write bigint as little-endian bytes (same encoding as scalars) */
  writeBigintLE(value: bigint, size: number): void {
    const bytes = new Uint8Array(size);
    let v = value;
    for (let i = 0; i < size; i++) {
      bytes[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    this.parts.push(bytes);
  }

  /** Write variable-length field with 2-byte big-endian length prefix */
  writeVar(data: Uint8Array): void {
    if (data.length > 0xffff) {
      throw new EncodingError('Variable field too long', EncodingErrorCode.TooLong);
    }
    const lenBuf = new Uint8Array(2);
    new DataView(lenBuf.buffer).setUint16(0, data.length, false); // big-endian
    this.parts.push(lenBuf);
    this.parts.push(data);
  }

  toBytes(): Uint8Array {
    const totalLen = this.parts.reduce((sum, p) => sum + p.length, 0);
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const part of this.parts) {
      result.set(part, offset);
      offset += part.length;
    }
    return result;
  }
}

/**
 * Reader helper with offset tracking and bounds checking.
 */
class Reader {
  private readonly view: DataView;
  private offset = 0;

  constructor(private readonly data: Uint8Array) {
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  }

  private ensureBytes(n: number): void {
    if (this.offset + n > this.data.length) {
      throw new EncodingError(
        `Data too short: need ${n} bytes at offset ${this.offset}`,
        EncodingErrorCode.TooShort
      );
    }
  }

  readElement(group: Group): GroupElement {
    const size = group.elementSize;
    this.ensureBytes(size);
    const bytes = this.data.subarray(this.offset, this.offset + size);
    this.offset += size;
    const elem = group.elementFromBytes(bytes);
    if (elem.equals(group.identity())) {
      throw new EncodingError('Identity point not allowed', EncodingErrorCode.InvalidPoint);
    }
    return elem;
  }

  readScalar(group: Group): Scalar {
    const size = group.scalarSize;
    this.ensureBytes(size);
    const bytes = this.data.subarray(this.offset, this.offset + size);
    this.offset += size;
    try {
      return group.scalarFromBytes(bytes);
    } catch {
      throw new EncodingError('Invalid scalar encoding', EncodingErrorCode.InvalidScalar);
    }
  }

  /** Read little-endian bigint */
  readBigintLE(size: number): bigint {
    this.ensureBytes(size);
    let value = 0n;
    for (let i = size - 1; i >= 0; i--) {
      value = (value << 8n) | BigInt(this.data[this.offset + i]!);
    }
    this.offset += size;
    return value;
  }

  /** Read variable-length field with 2-byte big-endian length prefix */
  readVar(): Uint8Array {
    this.ensureBytes(2);
    const len = this.view.getUint16(this.offset, false); // big-endian
    this.offset += 2;
    this.ensureBytes(len);
    const result = this.data.slice(this.offset, this.offset + len);
    this.offset += len;
    return result;
  }

  checkExact(): void {
    if (this.offset !== this.data.length) {
      throw new EncodingError(
        `Trailing data: ${this.data.length - this.offset} bytes`,
        EncodingErrorCode.TrailingData
      );
    }
  }
}

// --- IssuanceRequest: K[32] || len(pok)[2] || pok[...] ---

export function encodeIssuanceRequest(req: IssuanceRequest): Uint8Array {
  const w = new Writer();
  w.writeElement(req.K);
  w.writeVar(req.pok);
  return w.toBytes();
}

export function decodeIssuanceRequest(group: Group, data: Uint8Array): IssuanceRequest {
  const r = new Reader(data);
  const K = r.readElement(group);
  const pok = r.readVar();
  r.checkExact();
  return { K, pok };
}

// --- IssuanceResponse: A[32] || e[32] || c[32] || ctx[32] || len(pok)[2] || pok[...] ---

export function encodeIssuanceResponse(
  group: Group,
  resp: IssuanceResponse & { ctx: Scalar }
): Uint8Array {
  const w = new Writer();
  w.writeElement(resp.A);
  w.writeScalar(resp.e);
  w.writeBigintLE(resp.c, group.scalarSize);
  w.writeScalar(resp.ctx);
  w.writeVar(resp.pok);
  return w.toBytes();
}

export function decodeIssuanceResponse(
  group: Group,
  data: Uint8Array
): IssuanceResponse & { ctx: Scalar } {
  const r = new Reader(data);
  const A = r.readElement(group);
  const e = r.readScalar(group);
  const c = r.readBigintLE(group.scalarSize);
  const ctx = r.readScalar(group);
  const pok = r.readVar();
  r.checkExact();
  return { A, e, c, ctx, pok };
}

// --- SpendProof: k[32] || s[32] || ctx[32] || A'[32] || B_bar[32] || Com[L*32] || len(pok)[2] || pok[...] ---

export function encodeSpendProof(group: Group, proof: SpendProof): Uint8Array {
  const w = new Writer();
  w.writeScalar(proof.k);
  w.writeBigintLE(proof.s, group.scalarSize);
  w.writeScalar(proof.ctx);
  w.writeElement(proof.APrime);
  w.writeElement(proof.BBar);
  for (const com of proof.Com) {
    w.writeElement(com);
  }
  w.writeVar(proof.pok);
  return w.toBytes();
}

export function decodeSpendProof(group: Group, L: number, data: Uint8Array): SpendProof {
  if (L < 1 || L > 128) {
    throw new EncodingError('L must be 1-128', EncodingErrorCode.InvalidL);
  }
  const r = new Reader(data);
  const k = r.readScalar(group);
  const s = r.readBigintLE(group.scalarSize);
  const ctx = r.readScalar(group);
  const APrime = r.readElement(group);
  const BBar = r.readElement(group);
  const Com: GroupElement[] = [];
  for (let i = 0; i < L; i++) {
    Com.push(r.readElement(group));
  }
  const pok = r.readVar();
  r.checkExact();
  return { k, s, ctx, APrime, BBar, Com, pok };
}

// --- Refund: A*[32] || e*[32] || t[32] || len(pok)[2] || pok[...] ---

export function encodeRefund(group: Group, refund: Refund): Uint8Array {
  const w = new Writer();
  w.writeElement(refund.AStar);
  w.writeScalar(refund.eStar);
  w.writeBigintLE(refund.t, group.scalarSize);
  w.writeVar(refund.pok);
  return w.toBytes();
}

export function decodeRefund(group: Group, data: Uint8Array): Refund {
  const r = new Reader(data);
  const AStar = r.readElement(group);
  const eStar = r.readScalar(group);
  const t = r.readBigintLE(group.scalarSize);
  const pok = r.readVar();
  r.checkExact();
  return { AStar, eStar, t, pok };
}

// --- CreditToken: A[32] || e[32] || k[32] || r[32] || c[32] || ctx[32] = 192 bytes ---

export function encodeCreditToken(group: Group, token: CreditToken): Uint8Array {
  const w = new Writer();
  w.writeElement(token.A);
  w.writeScalar(token.e);
  w.writeScalar(token.k);
  w.writeScalar(token.r);
  w.writeBigintLE(token.c, group.scalarSize);
  w.writeScalar(token.ctx);
  return w.toBytes();
}

export function decodeCreditToken(group: Group, data: Uint8Array): CreditToken {
  const r = new Reader(data);
  const A = r.readElement(group);
  const e = r.readScalar(group);
  const k = r.readScalar(group);
  const rScalar = r.readScalar(group);
  const c = r.readBigintLE(group.scalarSize);
  const ctx = r.readScalar(group);
  r.checkExact();
  return { A, e, k, r: rScalar, c, ctx };
}

// --- IssuanceState: r[32] || k[32] || ctx[32] = 96 bytes ---

export function encodeIssuanceState(state: IssuanceState): Uint8Array {
  const w = new Writer();
  w.writeScalar(state.r);
  w.writeScalar(state.k);
  w.writeScalar(state.ctx);
  return w.toBytes();
}

export function decodeIssuanceState(group: Group, data: Uint8Array): IssuanceState {
  const reader = new Reader(data);
  const r = reader.readScalar(group);
  const k = reader.readScalar(group);
  const ctx = reader.readScalar(group);
  reader.checkExact();
  return { r, k, ctx };
}

// --- SpendState: r[32] || k[32] || m[32] || ctx[32] = 128 bytes ---

export function encodeSpendState(group: Group, state: SpendState): Uint8Array {
  const w = new Writer();
  w.writeScalar(state.rStar);
  w.writeScalar(state.kStar);
  w.writeBigintLE(state.m, group.scalarSize);
  w.writeScalar(state.ctx);
  return w.toBytes();
}

export function decodeSpendState(group: Group, data: Uint8Array): SpendState {
  const reader = new Reader(data);
  const rStar = reader.readScalar(group);
  const kStar = reader.readScalar(group);
  const m = reader.readBigintLE(group.scalarSize);
  const ctx = reader.readScalar(group);
  reader.checkExact();
  return { rStar, kStar, m, ctx };
}

// --- PrivateKey: x[32] = 32 bytes ---

export function encodePrivateKey(sk: PrivateKey): Uint8Array {
  return sk.x.toBytes();
}

export function decodePrivateKey(group: Group, data: Uint8Array): PrivateKey {
  const reader = new Reader(data);
  const x = reader.readScalar(group);
  reader.checkExact();
  return { x };
}

// --- PublicKey: W[32] = 32 bytes ---

export function encodePublicKey(pk: PublicKey): Uint8Array {
  return pk.W.toBytes();
}

export function decodePublicKey(group: Group, data: Uint8Array): PublicKey {
  const reader = new Reader(data);
  const W = reader.readElement(group);
  reader.checkExact();
  return { W };
}
