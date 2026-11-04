/**
 * Linear relations of draft-irtf-cfrg-sigma-protocols-03, Section 3.
 */

import { normalizeZ } from '@noble/curves/abstract/curve.js';
import { mod } from '@noble/curves/abstract/modular.js';
import {
  type Ciphersuite,
  type Point,
  SigmaError,
  deserializeElement,
  deserializeScalar,
  serializeScalar,
} from './ciphersuites.js';
import { type Effect, type Job, mulAll } from './effects.js';

/** (element_index, coeff) */
export type ImageTerm = readonly [element: number, coeff: bigint];
/** (scalar_index, element_index, coeff) */
export type Term = readonly [scalar: number, element: number, coeff: bigint];

/** One row of the linear map (Section 3.2). */
export interface Equation {
  readonly image: readonly ImageTerm[];
  readonly terms: readonly Term[];
}

const U32_MAX = 0xffffffff;

function le32(out: number[], value: number): void {
  out.push(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
}

/**
 * A LinearRelation (Section 3.2): elements[0] is the generator, and every
 * further element is registered with {@link addElements}.
 */
export class LinearRelation {
  readonly elements: Point[];
  readonly equations: Equation[] = [];
  private serialized: Uint8Array | undefined;

  constructor(readonly suite: Ciphersuite) {
    this.elements = [suite.Point.BASE];
  }

  /** Registers group elements; returns the index of the first one. */
  addElements(...points: Point[]): number {
    this.serialized = undefined;
    const first = this.elements.length;
    this.elements.push(...points);
    return first;
  }

  /** Appends `sum(image) = sum(terms)`. Coefficients are reduced mod p. */
  addEquation(image: readonly ImageTerm[], terms: readonly Term[]): void {
    this.serialized = undefined;
    const p = this.suite.order;
    this.equations.push({
      image: image.map(([e, c]) => [e, mod(c, p)] as const),
      terms: terms.map(([s, e, c]) => [s, e, mod(c, p)] as const),
    });
  }

  /** num_scalars(instance): one past the largest scalar index. */
  get numScalars(): number {
    let n = 0;
    for (const eq of this.equations) for (const [s] of eq.terms) n = Math.max(n, s + 1);
    return n;
  }

  /** SerializeLinearRelation (Section 3.6). Cached until the relation changes. */
  serialize(): Uint8Array {
    if (this.serialized) return this.serialized;
    const { suite } = this;
    const head: number[] = [];
    const parts: Uint8Array[] = [];
    const flush = (): void => {
      parts.push(Uint8Array.from(head));
      head.length = 0;
    };
    le32(head, this.equations.length);
    for (const { image, terms } of this.equations) {
      le32(head, image.length);
      for (const [e, c] of image) {
        le32(head, e);
        flush();
        parts.push(serializeScalar(suite, c));
      }
      le32(head, terms.length);
      for (const [s, e, c] of terms) {
        le32(head, s);
        le32(head, e);
        flush();
        parts.push(serializeScalar(suite, c));
      }
    }
    flush();
    const rest = this.elements.slice(1);
    if (rest.some((p) => p.is0())) throw new SigmaError('identity element in relation');
    // One batched inversion instead of one per element.
    for (const p of normalizeZ(suite.Point, rest)) parts.push(p.toBytes(true));
    let len = 0;
    for (const p of parts) len += p.length;
    const out = new Uint8Array(len);
    let off = 0;
    for (const p of parts) {
      out.set(p, off);
      off += p.length;
    }
    this.serialized = out;
    return out;
  }

  /** Parses SerializeLinearRelation output. Does not validate the instance. */
  static deserialize(suite: Ciphersuite, bytes: Uint8Array): LinearRelation {
    let off = 0;
    const take = (n: number): Uint8Array => {
      if (off + n > bytes.length) throw new SigmaError('truncated relation');
      const out = bytes.subarray(off, off + n);
      off += n;
      return out;
    };
    const u32 = (): number => {
      const b = take(4);
      return ((b[0] ?? 0) | ((b[1] ?? 0) << 8) | ((b[2] ?? 0) << 16) | ((b[3] ?? 0) << 24)) >>> 0;
    };
    const scalar = (): bigint => deserializeScalar(suite, take(suite.Ns));
    const rel = new LinearRelation(suite);
    const numEquations = u32();
    for (let i = 0; i < numEquations; i++) {
      const image: ImageTerm[] = [];
      for (let n = u32(); n > 0; n--) image.push([u32(), scalar()]);
      const terms: Term[] = [];
      for (let n = u32(); n > 0; n--) terms.push([u32(), u32(), scalar()]);
      rel.equations.push({ image, terms });
    }
    if ((bytes.length - off) % suite.Ne !== 0) throw new SigmaError('trailing bytes in relation');
    while (off < bytes.length) rel.elements.push(deserializeElement(suite, take(suite.Ne)));
    return rel;
  }

  /**
   * ValidateInstance (Section 3.5). Throws on an invalid instance and
   * returns image(instance), which both prover and verifier need.
   */
  validate(): Point[] {
    const { elements, equations, suite } = this;
    const fail = (why: string): never => {
      throw new SigmaError(`invalid instance: ${why}`);
    };
    if (equations.length === 0) fail('no equations'); // 1
    if (equations.length > U32_MAX || elements.length > U32_MAX + 1) fail('too large'); // 3
    if (!elements[0]?.equals(suite.Point.BASE)) fail('elements[0] is not the generator'); // 7
    if (elements.some((e) => e.is0())) fail('identity element'); // 8
    let numTerms = 0;
    for (const { terms } of equations) {
      numTerms += terms.length;
      for (const [s] of terms) {
        if (!Number.isInteger(s) || s < 0 || s > U32_MAX) fail('index out of range'); // 3, 4
      }
    }
    const numScalars = this.numScalars;
    // Section 3.5, step 6: every scalar must occur in a term. Check before
    // allocating so a sparse, attacker-supplied index cannot amplify memory use.
    if (numScalars > numTerms) fail('unused scalar');
    const elementUsed = new Uint8Array(elements.length);
    const scalarUsed = new Uint8Array(numScalars);
    const index = (i: number, bound: number): number =>
      Number.isInteger(i) && i >= 0 && i < bound ? i : fail('index out of range'); // 3, 4
    for (const { image, terms } of equations) {
      if (image.length === 0 || terms.length === 0) fail('empty equation side'); // 2
      for (const [e] of image) elementUsed[index(e, elements.length)] = 1;
      for (const [s, e] of terms) {
        scalarUsed[index(s, numScalars)] = 1;
        elementUsed[index(e, elements.length)] = 1;
      }
    }
    if (elementUsed.subarray(1).includes(0)) fail('unused element'); // 5
    if (scalarUsed.includes(0)) fail('unused scalar'); // 6
    const image = equations.map((eq) => lincombPublic(this, eq.image));
    if (image.some((p) => p.is0())) fail('identity image'); // 9
    // 10: some equation gives every column a non-identity entry.
    const columnDone = new Uint8Array(numScalars);
    let remaining = numScalars;
    for (const { terms } of equations) {
      if (remaining === 0) break;
      const column = new Map<number, Point>();
      for (const [s, e, c] of terms) {
        if (columnDone[s]) continue;
        const term = scale(elements[e] ?? fail('index'), c, suite.order);
        column.set(s, column.get(s)?.add(term) ?? term);
      }
      for (const [s, p] of column) {
        if (!p.is0()) {
          columnDone[s] = 1;
          remaining--;
        }
      }
    }
    if (remaining > 0) fail('identity column'); // 10
    return image;
  }

  /**
   * The prover commitment map(instance, nonces) (Section 4.2.1). Terms on
   * the same element are merged, so each distinct element costs one
   * constant-time multiplication, all batched.
   *
   * `openings` optionally gives, for an element index, a representation
   * sum(coeff * elements[e]) known to the prover. Terms on that element are
   * then committed through the representation, which lets the prover use
   * fixed-base multiplications instead of a variable-base one. A wrong
   * opening only produces a proof that fails to verify.
   */
  *commit(
    nonces: readonly bigint[],
    openings?: ReadonlyMap<number, readonly ImageTerm[]>
  ): Effect<Point[]> {
    const p = this.suite.order;
    const sums = this.equations.map(({ terms }) => {
      const byElement = new Map<number, bigint>();
      const add = (e: number, k: bigint): void => {
        byElement.set(e, mod((byElement.get(e) ?? 0n) + k, p));
      };
      for (const [s, e, c] of terms) {
        const k = c * (nonces[s] ?? 0n);
        const opening = openings?.get(e);
        if (opening) for (const [e2, c2] of opening) add(e2, k * c2);
        else add(e, k);
      }
      return byElement;
    });
    return yield* this.evaluate(sums, true);
  }

  /**
   * SimulateCommitment (Section 4.4): map(instance, response) -
   * challenge * image. Only public values are involved.
   */
  *simulate(
    challenge: bigint,
    response: readonly bigint[],
    image: readonly Point[]
  ): Effect<Point[]> {
    const p = this.suite.order;
    const minusC = mod(-challenge, p);
    const extra: (readonly [Point | undefined, bigint])[] = [];
    const sums = this.equations.map(({ terms, image: imageTerms }, i) => {
      const byElement = new Map<number, bigint>();
      for (const [s, e, c] of terms) {
        byElement.set(e, mod((byElement.get(e) ?? 0n) + c * (response[s] ?? 0n), p));
      }
      // A single-term image (the common case) is emitted on its element, in
      // the same group: noble merges it with a term on that element, while a
      // native backend keeps it apart to share the scalar -c across equations.
      const single = imageTerms.length === 1 ? imageTerms[0] : undefined;
      const entry: readonly [Point | undefined, bigint] = single
        ? [this.elements[single[0]], mod(single[1] * minusC, p)]
        : [image[i], minusC];
      extra.push(entry);
      return byElement;
    });
    return yield* this.evaluate(sums, false, extra);
  }

  /**
   * sum_e k_e * elements[e] for every equation, all terms in one batch; the
   * driver picks the backend for each. `extra[i] = [P, k]` adds k * P.
   */
  private *evaluate(
    sums: readonly ReadonlyMap<number, bigint>[],
    secret: boolean,
    extra: readonly (readonly [Point | undefined, bigint])[] = []
  ): Effect<Point[]> {
    const { suite } = this;
    const jobs: Job[] = [];
    const slots: number[][] = [];
    const acc = sums.map((byElement, i) => {
      const mine: number[] = [];
      const sum = suite.Point.ZERO;
      for (const [e, k] of byElement) {
        const base = this.elements[e];
        // Never skip a secret zero: with openings it can be a hidden bit.
        if (!base || (!secret && k === 0n)) continue;
        mine.push(jobs.push([base, k, secret, i]) - 1);
      }
      const [img, k] = extra[i] ?? [undefined, 0n];
      if (img && (secret || k !== 0n)) mine.push(jobs.push([img, k, secret, i]) - 1);
      slots.push(mine);
      return sum;
    });
    const results = yield* mulAll(jobs);
    return acc.map((sum, i) =>
      (slots[i] ?? []).reduce((s, j) => s.add(results[j] ?? suite.Point.ZERO), sum)
    );
  }
}

function scale(point: Point, coeff: bigint, p: bigint): Point {
  if (coeff === 1n) return point;
  return coeff === p - 1n ? point.negate() : point.multiplyUnsafe(coeff);
}

function lincombPublic(rel: LinearRelation, terms: readonly ImageTerm[]): Point {
  let acc = rel.suite.Point.ZERO;
  for (const [e, c] of terms) {
    const base = rel.elements[e];
    if (base) acc = acc.add(scale(base, c, rel.suite.order));
  }
  return acc;
}
