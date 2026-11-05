/**
 * EC-ACT: Anonymous Credit Tokens, draft-schlesinger-mole-ec-act-00.
 *
 * Section numbers in comments refer to that draft unless stated otherwise.
 */

import { invertCt, mod } from '@noble/curves/abstract/modular.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import {
  deriveSessionId,
  type ImageTerm,
  type Job,
  LinearRelation,
  mulMany,
  P256,
  proveCompact,
  registerFixedBase,
  verifyCompact,
} from 'sigma-proofs';
import { ACTError } from './errors.ts';
import {
  deriveKeyScalar,
  deriveNonces,
  deriveScalars,
  hashToGroup,
  hashToScalar,
  i2osp,
  NSEED,
  ORDER,
  Point,
  serializeElement,
  serializeScalar,
  u16Prefixed,
} from './group.ts';

/** Source of randomness: random(n) of EC-IHAT Section 2. */
export type Random = (n: number) => Uint8Array;

/** Ciphersuite identifier of EC-ACT(P-256, SHA-256) (Section 5.1). */
export const IDENTIFIER = 'P256-SHA256';
/** MAX_BIT_LENGTH for P-256 (Section 5.1). */
export const MAX_BIT_LENGTH = 64;
/** Compact NARG ciphersuite of the proofs (Section 4.4). */
const SIGMA_SUITE = 'sigma-proofs_Shake128_P256';

/** The EC-ACT configuration (Section 4.1). */
export interface Params {
  /** Balance width: amounts are in [0, 2^L). */
  readonly L: number;
  /** ctx_proto. */
  readonly ctxProto: Uint8Array;
  readonly H1: Point;
  readonly H2: Point;
  readonly H3: Point;
  readonly H4: Point;
}

/** CreateCredentialProtocolContext (Section 4.1). */
export const createProtocolContext = (identifier: string): Uint8Array =>
  utf8ToBytes(`EC-ACTv1-${identifier}`);

/**
 * Instantiates the configuration at balance width L (Section 4.1).
 *
 * `protocolContext` overrides ctx_proto. Its only use is interoperating with
 * implementations of pre-publication drafts, such as act-rs, which uses
 * `ACTv1-P256-SHA256`; everything else is unchanged.
 */
export function createParams(L: number, options: { protocolContext?: Uint8Array } = {}): Params {
  if (!Number.isInteger(L) || L < 1 || L > MAX_BIT_LENGTH) {
    throw new ACTError('Value', `L must be an integer in [1, ${MAX_BIT_LENGTH}]`);
  }
  const ctxProto = options.protocolContext ?? createProtocolContext(IDENTIFIER);
  // Section 4.1.1. Fixed-base tables make every multiplication on them cheap.
  const gen = (label: string): Point =>
    registerFixedBase(hashToGroup(ctxProto, utf8ToBytes(label)));
  return { L, ctxProto, H1: gen('GenH1'), H2: gen('GenH2'), H3: gen('GenH3'), H4: gen('GenH4') };
}

// ---------------------------------------------------------------------------
// Records (Sections 4.5, 4.6)
// ---------------------------------------------------------------------------

export interface KeyPair {
  readonly skM: bigint;
  readonly pkM: Point;
}

export interface ClientIssuanceState {
  readonly k: bigint;
  readonly r: bigint;
  readonly K: Point;
}

export interface IssueRequestMessage {
  readonly K: Point;
  readonly pok: Uint8Array;
}

export interface IssueResponseMessage {
  readonly A: Point;
  readonly e: bigint;
  readonly c: bigint;
  readonly pok: Uint8Array;
}

export interface Credential {
  readonly k: bigint;
  readonly c: bigint;
  readonly r: bigint;
  readonly A: Point;
  readonly e: bigint;
}

export interface ClientSpendState {
  readonly kstar: bigint;
  readonly rStar: bigint;
  readonly v1: bigint;
  readonly s: bigint;
  readonly a: bigint;
  readonly Kprime: Point;
}

export interface SpendMessage {
  readonly k: bigint;
  readonly s: bigint;
  readonly a: bigint;
  readonly Aprime: Point;
  readonly Bbar: Point;
  readonly Kn: Point;
  /** Bit commitments; empty for a refresh. */
  readonly com1: readonly Point[];
  /** Present exactly for a refresh (s = a = 0). */
  readonly comC: Point | undefined;
  readonly pok: Uint8Array;
}

export interface RefundMessage {
  readonly A: Point;
  readonly e: bigint;
  readonly t: bigint;
  readonly pok: Uint8Array;
}

/**
 * Credentials and Client states are single use (Section 6, "Single use of
 * Credentials and states"); this process refuses to use one twice.
 */
const consumed = new WeakSet<object>();
// Section 6 requires value consumption, including copies in this process.
// Retain only digests, for the module lifetime; eviction would permit reuse.
const consumedValues = new Set<string>();

function valueId(kind: string, scalars: readonly bigint[], point: Point): string {
  const bytes = concatBytes(
    utf8ToBytes(kind),
    ...scalars.map(serializeScalar),
    serializeElement(point)
  );
  try {
    return bytesToHex(sha256(bytes));
  } finally {
    bytes.fill(0);
  }
}

/**
 * Runs `body` with `value` claimed: a concurrent or later use fails, and
 * the claim becomes permanent only if `body` succeeds.
 */
async function once<R>(
  value: object,
  what: string,
  body: () => Promise<R>,
  identity?: string
): Promise<R> {
  // Claimed before the first await, so concurrent calls cannot both pass.
  if (consumed.has(value) || (identity !== undefined && consumedValues.has(identity))) {
    throw new ACTError('Value', `${what} was already used`);
  }
  consumed.add(value);
  if (identity !== undefined) consumedValues.add(identity);
  try {
    return await body();
  } catch (e) {
    consumed.delete(value);
    if (identity !== undefined) consumedValues.delete(identity);
    throw e;
  }
}

/** Runs a batch of P-256 multiplications, on WebCrypto where available. */
const mul = (jobs: readonly Job[]): Promise<Point[]> => mulMany(P256, jobs);

// ---------------------------------------------------------------------------
// Shared computations
// ---------------------------------------------------------------------------

const scalar = (x: bigint): bigint => mod(x, ORDER);
// Section 6: secret inversion must not use an operand-dependent Euclidean loop.
const inv = (x: bigint): bigint => invertCt(x, ORDER);

function maxAmount(params: Params): bigint {
  return (1n << BigInt(params.L)) - 1n;
}

/** Section 4.3: every amount is checked against 2^L before use. */
export function checkAmount(params: Params, x: bigint): void {
  if (typeof x !== 'bigint' || x < 0n || x > maxAmount(params)) {
    throw new ACTError('Amount', 'amount outside [0, 2^L)');
  }
}

/** CreateContextScalar (Section 4.2). */
export function contextScalar(params: Params, ctxCred: Uint8Array): bigint {
  return hashToScalar(
    concatBytes(u16Prefixed(ctxCred), utf8ToBytes('CredentialContext')),
    concatBytes(utf8ToBytes('HashToScalar-'), params.ctxProto)
  );
}

/** A credential context: its scalar ctx and the public point B + ctx * H4. */
interface Context {
  readonly ctx: bigint;
  readonly base: Point;
}

/**
 * Contexts are coarse (Section 6), so each configuration sees few; caching
 * B + ctx * H4 saves a multiplication in every operation.
 */
const contexts = new WeakMap<Params, Map<string, Context>>();
function context(params: Params, ctxCred: Uint8Array): Context {
  let cache = contexts.get(params);
  if (!cache) {
    cache = new Map();
    contexts.set(params, cache);
  }
  const key = bytesToHex(ctxCred);
  let cx = cache.get(key);
  if (!cx) {
    const ctx = contextScalar(params, ctxCred);
    cx = { ctx, base: Point.BASE.add(params.H4.multiplyUnsafe(ctx)) };
    // ponytail: unbounded only if contexts are not coarse; cap it anyway.
    if (cache.size >= 64) cache.clear();
    cache.set(key, cx);
  }
  return cx;
}

/** RangeWeights(m) (Section 4.3). */
export function rangeWeights(params: Params, m: bigint): bigint[] {
  checkAmount(params, m);
  const n = m.toString(2).length - (m === 0n ? 1 : 0);
  if (n === 0) return [];
  const w = Array.from({ length: n - 1 }, (_, j) => 1n << BigInt(j));
  w.push(m - (1n << BigInt(n - 1)) + 1n);
  return w;
}

/** The weights of a spend with amounts s and a; none for a refresh. */
export function spendWeights(params: Params, s: bigint, a: bigint): bigint[] {
  checkAmount(params, s);
  checkAmount(params, a);
  if (s + a > maxAmount(params)) throw new ACTError('Amount', 's + a >= 2^L');
  return s + a === 0n ? [] : rangeWeights(params, maxAmount(params) - (s + a));
}

/**
 * Bits(x, weights) (Section 4.3), as 0n/1n. Arithmetic only: no branch on x.
 * ponytail: JS BigInt is not constant time; this is best effort.
 */
function bits(x: bigint, weights: readonly bigint[]): bigint[] {
  const n = weights.length;
  if (n === 0) return [];
  const top = (x >> BigInt(n - 1)) & 1n;
  const rest = x - top * (weights[n - 1] ?? 0n);
  return [...Array.from({ length: n - 1 }, (_, j) => (rest >> BigInt(j)) & 1n), top];
}

/**
 * b * P for a secret bit b, as a branch-free select between the identity
 * (0 : 1 : 0) and P in projective coordinates.
 * ponytail: BigInt arithmetic is best-effort constant time, like noble.
 */
function select(b: bigint, P: Point): Point {
  const nb = 1n - b;
  return new Point(b * P.X, b * P.Y + nb, b * P.Z);
}

const Z = Point.ZERO;

/** sum_j weights[j] * points[j] by Horner over the public weight bits. */
function weightedSum(points: readonly Point[], weights: readonly bigint[]): Point {
  let acc = Point.ZERO;
  const top = Math.max(0, ...weights.map((w) => w.toString(2).length));
  for (let bit = BigInt(top - 1); bit >= 0n; bit--) {
    acc = acc.double();
    points.forEach((p, j) => {
      if (((weights[j] ?? 0n) >> bit) & 1n) acc = acc.add(p);
    });
  }
  return acc;
}

/** Tag(label, bindings) (Section 4.4.1). */
function tag(params: Params, label: string, bindings: readonly Uint8Array[] = []): Uint8Array {
  return concatBytes(
    params.ctxProto,
    utf8ToBytes(`-${label}-CMPT-with-${SIGMA_SUITE}`),
    ...bindings.map(u16Prefixed)
  );
}

/** Prove (Section 4.4.3) with ProverNonces (Section 4.4.2). */
async function prove(
  params: Params,
  tagBytes: Uint8Array,
  relation: LinearRelation,
  witness: readonly bigint[],
  random: Random,
  openings?: ReadonlyMap<number, readonly ImageTerm[]>
): Promise<Uint8Array> {
  const sessionId = deriveSessionId(tagBytes);
  const instance = relation.serialize();
  const secret = concatBytes(...witness.map(serializeScalar));
  const nonces = deriveNonces(
    params.ctxProto,
    secret,
    'nonce',
    concatBytes(sessionId, i2osp(instance.length, 4), instance),
    random(NSEED),
    witness.length
  );
  secret.fill(0);
  return await proveCompact(sessionId, relation, witness, nonces, openings);
}

/** Verify (Section 4.4.3). */
async function verify(
  tagBytes: Uint8Array,
  relation: LinearRelation,
  pok: Uint8Array
): Promise<void> {
  if (!(await verifyCompact(deriveSessionId(tagBytes), relation, pok))) {
    throw new ACTError('Verify', 'proof verification failed');
  }
}

/** Relation Commitment(H2, H3, K) (Section 4.5.2). */
function commitmentRelation(params: Params, K: Point): LinearRelation {
  const rel = new LinearRelation(P256);
  rel.addElements(params.H2, params.H3, K);
  rel.addEquation(
    [[3, 1n]],
    [
      [0, 1, 1n],
      [1, 2, 1n],
    ]
  );
  return rel;
}

/** Relation Signature(A, X_A, X_G) (Section 4.5.3). */
function signatureRelation(A: Point, XA: Point, XG: Point): LinearRelation {
  const rel = new LinearRelation(P256);
  rel.addElements(A, XA, XG);
  rel.addEquation([[2, 1n]], [[0, 1, 1n]]);
  rel.addEquation([[3, 1n]], [[0, 0, 1n]]);
  return rel;
}

// Witness indices of the Spend relation.
const [E, R2, R3, C, R, KSTAR, RN] = [0, 1, 2, 3, 4, 5, 6];
const FIXED_SCALARS = 7;
// Element indices of the Spend relation; the generator is 0.
const [EL_H1, EL_H2, EL_H3, EL_A_PRIME, EL_B_BAR, EL_A_BAR, EL_H1_PRIME, EL_K_N] = [
  1, 2, 3, 4, 5, 6, 7, 8,
];
const FIXED_ELEMENTS = 9;

/**
 * Relation Spend (Section 4.6.1), compiled in declaration order. Raises
 * VerifyError when the commitments do not match the shape fixed by s and a.
 */
function spendRelation(
  params: Params,
  Aprime: Point,
  Bbar: Point,
  Abar: Point,
  H1prime: Point,
  Kn: Point,
  s: bigint,
  a: bigint,
  com1: readonly Point[],
  comC: Point | undefined
): LinearRelation {
  const w = spendWeights(params, s, a);
  const n = w.length;
  const refresh = s + a === 0n;
  if (refresh !== (comC !== undefined) || com1.length !== n) {
    throw new ACTError('Verify', 'spend shape does not match its amounts');
  }
  const rel = new LinearRelation(P256);
  rel.addElements(params.H1, params.H2, params.H3, Aprime, Bbar, Abar, H1prime, Kn);
  rel.addEquation(
    [[EL_A_BAR, 1n]],
    [
      [E, EL_A_PRIME, -1n],
      [R2, EL_B_BAR, 1n],
    ]
  );
  rel.addEquation(
    [[EL_H1_PRIME, 1n]],
    [
      [R3, EL_B_BAR, 1n],
      [C, EL_H1, -1n],
      [R, EL_H3, -1n],
    ]
  );
  rel.addEquation(
    [[EL_K_N, 1n]],
    [
      [KSTAR, EL_H2, 1n],
      [RN, EL_H3, 1n],
    ]
  );
  if (comC !== undefined) {
    rel.addElements(comC);
    rel.addEquation(
      [[FIXED_ELEMENTS, 1n]],
      [
        [C, EL_H1, 1n],
        [FIXED_SCALARS, EL_H3, 1n],
      ]
    );
    return rel;
  }
  rel.addElements(...com1);
  const [b1, s1, u1] = [FIXED_SCALARS, FIXED_SCALARS + n, FIXED_SCALARS + 2 * n];
  for (let j = 0; j < n; j++) {
    const com = FIXED_ELEMENTS + j;
    rel.addEquation(
      [[com, 1n]],
      [
        [b1 + j, EL_H1, 1n],
        [s1 + j, EL_H3, 1n],
      ]
    );
    rel.addEquation(
      [[com, 1n]],
      [
        [b1 + j, com, 1n],
        [u1 + j, EL_H3, 1n],
      ]
    );
  }
  rel.addEquation(
    [[EL_K_N, 1n], [EL_H1, s], ...w.map((wj, j) => [FIXED_ELEMENTS + j, wj] as const)],
    [
      [C, EL_H1, 1n],
      [KSTAR, EL_H2, 1n],
      [RN, EL_H3, 1n],
      ...w.map((wj, j) => [s1 + j, EL_H3, wj] as const),
    ]
  );
  return rel;
}

/** SigningExponent (Section 4.5.1), returning e and x = e + skM. */
function signingExponent(
  params: Params,
  skM: bigint,
  label: string,
  XA: Point,
  random: Random
): { e: bigint; x: bigint } {
  const instance = concatBytes(u16Prefixed(utf8ToBytes(label)), u16Prefixed(serializeElement(XA)));
  const [e = 0n] = deriveNonces(
    params.ctxProto,
    serializeScalar(skM),
    'e',
    instance,
    random(NSEED),
    1
  );
  const x = scalar(e + skM);
  if (x === 0n) throw new ACTError('Derive', 'e + skM is zero');
  return { e, x };
}

/** Signs X_A as (A, e) and proves it under the tag of `label`. */
async function sign(
  params: Params,
  skM: bigint,
  label: string,
  XA: Point,
  random: Random
): Promise<{ A: Point; e: bigint; pok: Uint8Array }> {
  const { e, x } = signingExponent(params, skM, label, XA, random);
  const [A = Point.ZERO, XG = Point.ZERO] = await mul([
    [XA, inv(x), true],
    [Point.BASE, x, true],
  ]);
  const pok = await prove(params, tag(params, label), signatureRelation(A, XA, XG), [x], random);
  return { A, e, pok };
}

/**
 * Checks the Signature proof of (A, e) under pkM on the message
 * X_A = B + c * H1 + ctx * H4 + K, computing X_A and X_G in one batch.
 */
async function verifySignature(
  label: string,
  params: Params,
  pkM: Point,
  A: Point,
  e: bigint,
  c: bigint,
  cx: Context,
  K: Point,
  pok: Uint8Array
): Promise<void> {
  const [cH1 = Point.ZERO, eG = Point.ZERO] = await mul([
    [params.H1, c, false],
    [Point.BASE, e, false],
  ]);
  const XA = cx.base.add(cH1).add(K);
  await verify(tag(params, label), signatureRelation(A, XA, eG.add(pkM)), pok);
}

/** B + c * H1 + ctx * H4 + K: X_A of issuance and refunds (c, ctx public). */
async function signedMessage(params: Params, c: bigint, cx: Context, K: Point): Promise<Point> {
  const [cH1 = Point.ZERO] = await mul([[params.H1, c, false]]);
  return cx.base.add(cH1).add(K);
}

// ---------------------------------------------------------------------------
// Keys (Sections 3.4, 4.1.2)
// ---------------------------------------------------------------------------

/** G.DeriveKeyPair(seed, info). */
export async function deriveKeys(params: Params, seed: Uint8Array, info: string): Promise<KeyPair> {
  const skM = deriveKeyScalar(params.ctxProto, seed, info);
  const [pkM = Point.ZERO] = await mul([[Point.BASE, skM, true]]);
  return { skM, pkM };
}

/** G.GenerateKeyPair(). */
export function generateKeys(params: Params, random: Random = randomBytes): Promise<KeyPair> {
  return deriveKeys(params, random(NSEED), 'GenerateKeyPair');
}

// ---------------------------------------------------------------------------
// Issuance (Section 4.5)
// ---------------------------------------------------------------------------

/** IssueRequest (Section 4.5.2). Run by the Client. */
export async function issueRequest(
  params: Params,
  random: Random = randomBytes
): Promise<{ state: ClientIssuanceState; request: IssueRequestMessage }> {
  const [k = 0n, r = 0n] = deriveScalars(params.ctxProto, random(NSEED), 'IssueRequest', 2);
  const [kH2 = Point.ZERO, rH3 = Point.ZERO] = await mul([
    [params.H2, k, true],
    [params.H3, r, true],
  ]);
  const K = kH2.add(rH3);
  const pok = await prove(
    params,
    tag(params, 'IssueRequest'),
    commitmentRelation(params, K),
    [k, r],
    random
  );
  return { state: { k, r, K }, request: { K, pok } };
}

/** IssueResponse (Section 4.5.3). Run by the Moderator; verifies the request. */
export async function issueResponse(
  params: Params,
  skM: bigint,
  ctxCred: Uint8Array,
  c: bigint,
  request: IssueRequestMessage,
  random: Random = randomBytes
): Promise<IssueResponseMessage> {
  request = { ...request, pok: request.pok.slice() };
  ctxCred = ctxCred.slice();
  checkAmount(params, c);
  await verify(tag(params, 'IssueRequest'), commitmentRelation(params, request.K), request.pok);
  const XA = await signedMessage(params, c, context(params, ctxCred), request.K);
  const { A, e, pok } = await sign(params, skM, 'IssueResponse', XA, random);
  return { A, e, c, pok };
}

/**
 * FinalizeIssue (Section 4.5.4). Run by the Client; consumes `state` on
 * success.
 */
export async function finalizeIssue(
  params: Params,
  pkM: Point,
  ctxCred: Uint8Array,
  state: ClientIssuanceState,
  response: IssueResponseMessage
): Promise<Credential> {
  const original = state;
  state = { ...state };
  response = { ...response, pok: response.pok.slice() };
  return await once(
    original,
    'issuance state',
    async () => {
      checkAmount(params, response.c);
      const cx = context(params, ctxCred);
      const { A, e, c, pok } = response;
      await verifySignature('IssueResponse', params, pkM, A, e, c, cx, state.K, pok);
      return { k: state.k, c, r: state.r, A, e };
    },
    valueId('issuance', [state.k, state.r], state.K)
  );
}

// ---------------------------------------------------------------------------
// Spending (Section 4.6)
// ---------------------------------------------------------------------------

/**
 * ProveSpend (Section 4.6.2). Run by the Client; consumes `credential`.
 *
 * The returned state MUST be stored durably before `proof` leaves the Client.
 */
export async function proveSpend(
  params: Params,
  credential: Credential,
  ctxCred: Uint8Array,
  s: bigint,
  a: bigint,
  ctxSpend: Uint8Array,
  random: Random = randomBytes
): Promise<{ state: ClientSpendState; proof: SpendMessage }> {
  const snapshot = { ...credential };
  return once(
    credential,
    'credential',
    () => proveSpendBody(params, snapshot, ctxCred.slice(), s, a, ctxSpend.slice(), random),
    valueId('credential', [snapshot.k, snapshot.c, snapshot.r, snapshot.e], snapshot.A)
  );
}

async function proveSpendBody(
  params: Params,
  credential: Credential,
  ctxCred: Uint8Array,
  s: bigint,
  a: bigint,
  ctxSpend: Uint8Array,
  random: Random
): Promise<{ state: ClientSpendState; proof: SpendMessage }> {
  const { k, c, r, A, e } = credential;
  const { H1, H2, H3 } = params;
  checkAmount(params, s);
  checkAmount(params, a);
  if (s > c || c + a > maxAmount(params)) throw new ACTError('Amount', 'balance does not cover');
  const v1 = c - s;
  const refresh = s + a === 0n;
  const w = spendWeights(params, s, a);
  const n = w.length;
  const cx = context(params, ctxCred);

  const derived = deriveScalars(
    params.ctxProto,
    random(NSEED),
    'ProveSpend',
    4 + (refresh ? 1 : n)
  );
  const [r1 = 0n, r2 = 0n, kstar = 0n, rn = 0n] = derived;

  // Every fixed-base product of the spend, in one batch: k H2, r H3, c H1,
  // kstar H2, rn H3, then s1[j] H3 per bit, or rc H3 for a refresh.
  const blindings = derived.slice(4);
  const fixedProducts = await mul([
    [H2, k, true],
    [H3, r, true],
    [H1, c, true],
    [H2, kstar, true],
    [H3, rn, true],
    ...blindings.map((sj): Job => [H3, sj, true]),
  ]);
  const [kH2 = Z, rH3 = Z, cH1 = Z, kstarH2 = Z, rnH3 = Z, ...blindH3] = fixedProducts;

  // Rerandomize the signature.
  // H1_prime = B + k * H2 + ctx * H4, and B_msg = H1_prime + c * H1 + r * H3.
  const H1prime = cx.base.add(kH2);
  const Bmsg = H1prime.add(cH1).add(rH3);
  // One batch: A_bar = r2 * B_bar - e * A_prime = (r1 r2) * B_msg - (e r1 r2) * A.
  const r1r2 = scalar(r1 * r2);
  const [Aprime = Point.ZERO, Bbar = Point.ZERO, X = Point.ZERO, Y = Point.ZERO] = await mul([
    [A, r1r2, true],
    [Bmsg, r1, true],
    [Bmsg, r1r2, true],
    [A, scalar(e * r1r2), true],
  ]);
  const Abar = X.subtract(Y);
  const r3 = inv(r1);

  // Commit to the next Credential's nullifier.
  const Kn = kstarH2.add(rnH3);

  const witness = [e, r2, r3, c, r, kstar, rn];
  // The prover knows each commitment's opening on H1 and H3, which lets it
  // commit with fixed-base multiplications only.
  const openings = new Map<number, ImageTerm[]>();
  let com1: Point[] = [];
  let comC: Point | undefined;
  let rStar: bigint;
  if (!refresh) {
    const b1 = bits(v1, w);
    const s1 = blindings;
    com1 = b1.map((b, j) => select(b, H1).add(blindH3[j] ?? Z));
    const u1 = b1.map((b, j) => scalar((1n - b) * (s1[j] ?? 0n)));
    rStar = scalar(s1.reduce((acc, sj, j) => acc + (w[j] ?? 0n) * sj, rn));
    witness.push(...b1, ...s1, ...u1);
    for (const [j, b] of b1.entries()) {
      openings.set(FIXED_ELEMENTS + j, [
        [EL_H1, b],
        [EL_H3, s1[j] ?? 0n],
      ]);
    }
  } else {
    const rc = blindings[0] ?? 0n;
    comC = cH1.add(blindH3[0] ?? Z);
    rStar = scalar(rn + rc);
    witness.push(rc);
    openings.set(FIXED_ELEMENTS, [
      [EL_H1, c],
      [EL_H3, rc],
    ]);
  }

  const relation = spendRelation(params, Aprime, Bbar, Abar, H1prime, Kn, s, a, com1, comC);
  const pok = await prove(
    params,
    tag(params, 'Spend', [ctxSpend]),
    relation,
    witness,
    random,
    openings
  );

  // The commitment the refund signs, K_n + V1 (Section 4.6.2); it equals
  // v1 * H1 + kstar * H2 + r_star * H3, but costs no multiplication.
  const Kprime = Kn.add(comC ?? weightedSum(com1, w));
  return {
    state: { kstar, rStar, v1, s, a, Kprime },
    proof: { k, s, a, Aprime, Bbar, Kn, com1, comC, pok },
  };
}

const token: unique symbol = Symbol('VerifiedSpend');

/**
 * Evidence that a spend passed {@link verifySpend} under a given key and
 * contexts. Only {@link issueRefund} consumes it, so a raw, unverified spend
 * can never be signed.
 *
 * Before calling issueRefund, the Moderator MUST check it grants the top-up
 * `a`, and record `nullifier` atomically, failing if already present
 * (Section 4.6.3).
 */
export class VerifiedSpend {
  readonly #params: Params;
  readonly #skM: bigint;
  readonly #cx: Context;
  readonly #Kprime: Point;
  /** Serialized nullifier k, the key of the Moderator's nullifier store. */
  readonly nullifier: Uint8Array;
  readonly s: bigint;
  readonly a: bigint;

  /** @internal */
  constructor(
    t: typeof token,
    params: Params,
    skM: bigint,
    cx: Context,
    Kprime: Point,
    proof: SpendMessage
  ) {
    if (t !== token) throw new ACTError('Value', 'use verifySpend');
    this.#params = params;
    this.#skM = skM;
    this.#cx = cx;
    this.#Kprime = Kprime;
    this.nullifier = serializeScalar(proof.k);
    this.s = proof.s;
    this.a = proof.a;
  }

  /** @internal */
  static async refund(v: VerifiedSpend, t: bigint, random: Random): Promise<RefundMessage> {
    const params = v.#params;
    checkAmount(params, t);
    if (t > v.s + v.a) throw new ACTError('Amount', 't > s + a');
    const [skM, cx, Kprime] = [v.#skM, v.#cx, v.#Kprime];
    return await once(v, 'verified spend', async () => {
      const XA = await signedMessage(params, t, cx, Kprime);
      const { A, e, pok } = await sign(params, skM, 'Refund', XA, random);
      return { A, e, t, pok };
    });
  }
}

/** VerifySpend (Section 4.6.3). Run by the Moderator. */
export async function verifySpend(
  params: Params,
  skM: bigint,
  ctxCred: Uint8Array,
  ctxSpend: Uint8Array,
  proof: SpendMessage
): Promise<VerifiedSpend> {
  // Sections 4.6.3–4.6.4: authorize exactly the message checked before any await.
  proof = { ...proof, com1: [...proof.com1], pok: proof.pok.slice() };
  ctxSpend = ctxSpend.slice();
  const { k, s, a, Aprime, Bbar, Kn, com1, comC, pok } = proof;
  spendWeights(params, s, a); // amount checks precede verification (Section 6)
  const cx = context(params, ctxCred);
  const [Abar = Point.ZERO, kH2 = Point.ZERO] = await mul([
    [Aprime, skM, true],
    [params.H2, k, false],
  ]);
  const H1prime = cx.base.add(kH2);
  const relation = spendRelation(params, Aprime, Bbar, Abar, H1prime, Kn, s, a, com1, comC);
  await verify(tag(params, 'Spend', [ctxSpend]), relation, pok);
  return new VerifiedSpend(token, params, skM, cx, balanceCommitment(params, proof), proof);
}

/** BalanceCommitment (Section 4.6.4): K_n + V1. */
function balanceCommitment(params: Params, proof: SpendMessage): Point {
  const V1 = proof.comC ?? weightedSum(proof.com1, spendWeights(params, proof.s, proof.a));
  return proof.Kn.add(V1);
}

/**
 * IssueRefund (Section 4.6.4). Run by the Moderator, only on the result of
 * a successful {@link verifySpend}, and only once per verified spend.
 */
export function issueRefund(
  verified: VerifiedSpend,
  t: bigint,
  random: Random = randomBytes
): Promise<RefundMessage> {
  return VerifiedSpend.refund(verified, t, random);
}

/**
 * FinalizeRefund (Section 4.6.5). Run by the Client; consumes `state` on
 * success. The new Credential has balance c - s + t.
 */
export async function finalizeRefund(
  params: Params,
  pkM: Point,
  ctxCred: Uint8Array,
  state: ClientSpendState,
  refund: RefundMessage
): Promise<Credential> {
  const original = state;
  state = { ...state };
  refund = { ...refund, pok: refund.pok.slice() };
  return await once(
    original,
    'spend state',
    async () => {
      const { kstar, rStar, v1, s, a, Kprime } = state;
      const { t } = refund;
      checkAmount(params, t);
      if (t > s + a || v1 + t > maxAmount(params)) {
        throw new ACTError('Amount', 'invalid refund amount');
      }
      const cx = context(params, ctxCred);
      await verifySignature('Refund', params, pkM, refund.A, refund.e, t, cx, Kprime, refund.pok);
      return { k: kstar, c: v1 + t, r: rStar, A: refund.A, e: refund.e };
    },
    valueId('spend', [state.kstar, state.rStar, state.v1, state.s, state.a], state.Kprime)
  );
}

/** Nw, the witness length of a spend with amounts s and a (Section 4.7). */
export function spendWitnessCount(params: Params, s: bigint, a: bigint): number {
  return 7 + (s + a === 0n ? 1 : 3 * spendWeights(params, s, a).length);
}
