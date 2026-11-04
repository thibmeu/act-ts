/**
 * Encodings (Section 4.7 of draft-schlesinger-mole-ec-act-00).
 *
 * Messages use the draft's encodings. Credentials and Client states use the
 * draft's storage encoding (and its test-vector representation for states);
 * they hold secrets and must be stored accordingly.
 */

import { bytesToNumberBE } from '@noble/curves/utils.js';
import { concatBytes } from '@noble/hashes/utils.js';
import {
  type ClientIssuanceState,
  type ClientSpendState,
  type Credential,
  type IssueRequestMessage,
  type IssueResponseMessage,
  type KeyPair,
  type Params,
  type RefundMessage,
  type SpendMessage,
  checkAmount,
  spendWeights,
  spendWitnessCount,
} from './act.js';
import { ACTError } from './errors.js';
import {
  NE,
  NS,
  type Point,
  Point as PointCons,
  deserializeElementOrThrow,
  deserializeScalarOrThrow,
  i2osp,
  serializeElement,
  serializeScalar,
} from './group.js';

const u64 = (x: bigint): Uint8Array => i2osp(x, 8);

class Reader {
  private off = 0;
  constructor(private readonly bytes: Uint8Array) {}
  take(n: number): Uint8Array {
    if (this.off + n > this.bytes.length) throw new ACTError('Deserialize', 'truncated');
    const out = this.bytes.subarray(this.off, this.off + n);
    this.off += n;
    return out;
  }
  scalar(): bigint {
    return deserializeScalarOrThrow(this.take(NS));
  }
  element(): Point {
    return deserializeElementOrThrow(this.take(NE));
  }
  /** A uint64 amount, checked against 2^L (Section 4.3). */
  amount(params: Params): bigint {
    const x = bytesToNumberBE(this.take(8));
    checkAmount(params, x);
    return x;
  }
  /** A compact NARG string of `witnesses` + 1 canonical scalars. */
  pok(witnesses: number): Uint8Array {
    const pok = this.take((witnesses + 1) * NS);
    for (let i = 0; i < pok.length; i += NS) deserializeScalarOrThrow(pok.subarray(i, i + NS));
    return pok.slice();
  }
  finish(): void {
    if (this.off !== this.bytes.length) throw new ACTError('Deserialize', 'trailing bytes');
  }
}

function decode<T>(bytes: Uint8Array, read: (r: Reader) => T): T {
  const r = new Reader(bytes);
  const out = read(r);
  r.finish();
  return out;
}

// --- Keys -------------------------------------------------------------------

export const encodePublicKey = (pkM: Point): Uint8Array => serializeElement(pkM);
export const decodePublicKey = (bytes: Uint8Array): Point => decode(bytes, (r) => r.element());

/** The signing key skM, a secret. */
export const encodeSecretKey = (key: KeyPair): Uint8Array => serializeScalar(key.skM);
export function decodeSecretKey(bytes: Uint8Array): KeyPair {
  const skM = decode(bytes, (r) => r.scalar());
  if (skM === 0n) throw new ACTError('Deserialize', 'zero key');
  return { skM, pkM: PointCons.BASE.multiply(skM) };
}

// --- Messages ---------------------------------------------------------------

export const encodeIssueRequest = (m: IssueRequestMessage): Uint8Array =>
  concatBytes(serializeElement(m.K), m.pok);
export const decodeIssueRequest = (bytes: Uint8Array): IssueRequestMessage =>
  decode(bytes, (r) => ({ K: r.element(), pok: r.pok(2) }));

export const encodeIssueResponse = (m: IssueResponseMessage): Uint8Array =>
  concatBytes(serializeElement(m.A), serializeScalar(m.e), u64(m.c), m.pok);
export const decodeIssueResponse = (params: Params, bytes: Uint8Array): IssueResponseMessage =>
  decode(bytes, (r) => ({ A: r.element(), e: r.scalar(), c: r.amount(params), pok: r.pok(1) }));

export function encodeSpend(m: SpendMessage): Uint8Array {
  return concatBytes(
    serializeScalar(m.k),
    u64(m.s),
    u64(m.a),
    serializeElement(m.Aprime),
    serializeElement(m.Bbar),
    serializeElement(m.Kn),
    ...(m.comC ? [serializeElement(m.comC)] : m.com1.map(serializeElement)),
    m.pok
  );
}

/** Rejects amounts >= 2^L, s + a >= 2^L, and any shape other than s and a fix. */
export function decodeSpend(params: Params, bytes: Uint8Array): SpendMessage {
  return decode(bytes, (r) => {
    const k = r.scalar();
    const s = r.amount(params);
    const a = r.amount(params);
    const n = spendWeights(params, s, a).length; // AmountError before computing n
    const Aprime = r.element();
    const Bbar = r.element();
    const Kn = r.element();
    const refresh = s + a === 0n;
    const comC = refresh ? r.element() : undefined;
    const com1 = refresh ? [] : Array.from({ length: n }, () => r.element());
    const pok = r.pok(spendWitnessCount(params, s, a));
    return { k, s, a, Aprime, Bbar, Kn, com1, comC, pok };
  });
}

export const encodeRefund = (m: RefundMessage): Uint8Array =>
  concatBytes(serializeElement(m.A), serializeScalar(m.e), u64(m.t), m.pok);
export const decodeRefund = (params: Params, bytes: Uint8Array): RefundMessage =>
  decode(bytes, (r) => ({ A: r.element(), e: r.scalar(), t: r.amount(params), pok: r.pok(1) }));

// --- Client storage ---------------------------------------------------------

export const encodeCredential = (c: Credential): Uint8Array =>
  concatBytes(
    serializeScalar(c.k),
    u64(c.c),
    serializeScalar(c.r),
    serializeElement(c.A),
    serializeScalar(c.e)
  );
export const decodeCredential = (params: Params, bytes: Uint8Array): Credential =>
  decode(bytes, (r) => ({
    k: r.scalar(),
    c: r.amount(params),
    r: r.scalar(),
    A: r.element(),
    e: r.scalar(),
  }));

export const encodeIssuanceState = (s: ClientIssuanceState): Uint8Array =>
  concatBytes(serializeScalar(s.k), serializeScalar(s.r), serializeElement(s.K));
export const decodeIssuanceState = (bytes: Uint8Array): ClientIssuanceState =>
  decode(bytes, (r) => ({ k: r.scalar(), r: r.scalar(), K: r.element() }));

export const encodeSpendState = (s: ClientSpendState): Uint8Array =>
  concatBytes(
    serializeScalar(s.kstar),
    serializeScalar(s.rStar),
    u64(s.v1),
    u64(s.s),
    u64(s.a),
    serializeElement(s.Kprime)
  );
export const decodeSpendState = (params: Params, bytes: Uint8Array): ClientSpendState =>
  decode(bytes, (r) => ({
    kstar: r.scalar(),
    rStar: r.scalar(),
    v1: r.amount(params),
    s: r.amount(params),
    a: r.amount(params),
    Kprime: r.element(),
  }));
