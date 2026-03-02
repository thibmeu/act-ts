/**
 * Linear relation constraint system for sigma protocols.
 *
 * Implements Section 2.2.3 of draft-irtf-cfrg-sigma-protocols-01.
 *
 * A LinearRelation encodes a proof statement of the form:
 *   linear_map(witness) = image
 */

import type { Group, GroupElement } from './group.js';
import { LinearMap, type LinearCombination } from './linear-map.js';
import { concat } from './utils.js';

/** Maximum number of scalars to prevent DoS */
const MAX_SCALARS = 1024;
/** Maximum number of elements to prevent DoS */
const MAX_ELEMENTS = 1024;

/**
 * Encode a 32-bit integer as little-endian bytes.
 */
function u32le(value: number): Uint8Array {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, value, true); // little-endian
  return result;
}

/**
 * Encodes a proof statement for knowledge of a preimage under a linear map.
 *
 * @example
 * ```ts
 * // Schnorr proof: PoK{(x): X = x * G}
 * const relation = new LinearRelation(group);
 * const [varX] = relation.allocateScalars(1);
 * const [varG, varXPoint] = relation.allocateElements(2);
 * relation.appendEquation(varXPoint, [[varX, varG]]);
 * relation.setElements([[varG, G], [varXPoint, X]]);
 * // Image is automatically populated from equation LHS elements
 * ```
 */
export class LinearRelation {
  readonly linearMap: LinearMap;
  /** Indices into groupElements for each equation's LHS */
  readonly imageIndices: number[] = [];
  /** Cached instance label (computed lazily, invalidated on structure changes) */
  private _cachedInstanceLabel: Uint8Array | undefined;

  constructor(group: Group) {
    this.linearMap = new LinearMap(group);
  }

  /** Invalidate cached instance label when structure changes */
  private _invalidateCache(): void {
    this._cachedInstanceLabel = undefined;
  }

  /**
   * Image elements (LHS of equations), derived from groupElements via imageIndices.
   * This getter ensures image is always in sync with setElements.
   */
  get image(): readonly GroupElement[] {
    return this.imageIndices.map((idx) => {
      const elem = this.linearMap.groupElements[idx];
      if (elem === undefined) {
        throw new Error(`Image index ${idx} references unset element`);
      }
      return elem;
    });
  }

  /** The underlying group */
  get group(): Group {
    return this.linearMap.group;
  }

  /** Number of scalar variables (witness size) */
  get numScalars(): number {
    return this.linearMap.numScalars;
  }

  /** Number of constraints */
  get numConstraints(): number {
    return this.linearMap.numConstraints;
  }

  /**
   * Allocate scalar variables (witness components).
   *
   * @param n - Number of scalars to allocate
   * @returns Array of indices pointing to the new allocated scalars
   * @throws If allocation would exceed MAX_SCALARS (1024)
   */
  allocateScalars(n: number): number[] {
    if (n < 0) {
      throw new Error('Cannot allocate negative number of scalars');
    }
    const start = this.linearMap.numScalars;
    if (start + n > MAX_SCALARS) {
      throw new Error(`Cannot allocate ${n} scalars: would exceed limit of ${MAX_SCALARS}`);
    }
    this.linearMap.numScalars += n;

    const indices: number[] = [];
    for (let i = 0; i < n; i++) {
      indices.push(start + i);
    }
    return indices;
  }

  /**
   * Allocate group element slots (instance components).
   *
   * @param n - Number of elements to allocate
   * @returns Array of indices pointing to the new allocated element slots
   * @throws If allocation would exceed MAX_ELEMENTS (1024)
   */
  allocateElements(n: number): number[] {
    if (n < 0) {
      throw new Error('Cannot allocate negative number of elements');
    }
    const start = this.linearMap.groupElements.length;
    if (start + n > MAX_ELEMENTS) {
      throw new Error(`Cannot allocate ${n} elements: would exceed limit of ${MAX_ELEMENTS}`);
    }

    // Push identity placeholders
    for (let i = 0; i < n; i++) {
      this.linearMap.groupElements.push(this.linearMap.group.identity());
    }

    const indices: number[] = [];
    for (let i = 0; i < n; i++) {
      indices.push(start + i);
    }
    return indices;
  }

  /**
   * Append an equation: lhs = sum(scalars[i] * elements[j]) for (i, j) in rhs
   *
   * @param lhs - Index of the left-hand side element (the image)
   * @param rhs - Array of [scalarIndex, elementIndex] pairs
   */
  appendEquation(lhs: number, rhs: Array<[number, number]>): void {
    this._invalidateCache();
    const lc: LinearCombination = {
      scalarIndices: rhs.map(([s, _]) => s),
      elementIndices: rhs.map(([_, e]) => e),
    };

    this.linearMap.append(lc);

    // Store the LHS index - image is derived from groupElements via this index
    this.imageIndices.push(lhs);
  }

  /**
   * Set concrete values for allocated group elements.
   *
   * This also sets the image values automatically - elements referenced as
   * LHS in appendEquation() become the corresponding image values.
   *
   * @param elements - Array of [index, element] pairs
   */
  setElements(elements: Array<[number, GroupElement]>): void {
    this._invalidateCache();
    for (const [index, element] of elements) {
      if (index < 0 || index >= this.linearMap.groupElements.length) {
        throw new Error(
          `Element index ${index} out of bounds (valid: 0-${this.linearMap.groupElements.length - 1})`
        );
      }
      this.linearMap.groupElements[index] = element;
    }
  }

  /**
   * Compute a canonical instance label for Fiat-Shamir domain separation.
   *
   * This matches sigma-rs's `CanonicalLinearRelation::label()` format.
   * The canonicalization rebuilds the group element list by walking equations
   * in order, making the label independent of element allocation order.
   *
   * Output format:
   * ```
   * [num_equations: u32 LE]
   * per equation:
   *   [image_index: u32 LE]
   *   [num_terms: u32 LE]
   *   per term:
   *     [scalar_index: u32 LE]
   *     [element_index: u32 LE]
   * [all canonical group elements concatenated]
   * ```
   *
   * Results are cached; cache is invalidated when the relation structure changes.
   *
   * @returns The canonical instance label as bytes
   */
  getInstanceLabel(): Uint8Array {
    // Return cached result if available
    if (this._cachedInstanceLabel !== undefined) {
      return this._cachedInstanceLabel;
    }

    const lm = this.linearMap;
    const orig = lm.groupElements;

    // Canonical element list
    // Matches Rust's CanonicalLinearRelation behavior:
    // - RHS elements are deduplicated by original index (via WeightedGroupCache)
    // - Image elements ALWAYS get fresh canonical indices (not deduplicated)
    const canonElems: GroupElement[] = [];

    // Maps original element index -> canonical index (for RHS elements only)
    const rhsCache = new Map<number, number>();

    // Get or create a canonical index for an RHS element (with deduplication)
    const getOrCreateRhs = (origIdx: number): number => {
      const existing = rhsCache.get(origIdx);
      if (existing !== undefined) {
        return existing;
      }
      const elem = orig[origIdx];
      if (elem === undefined) {
        throw new Error(`Invalid element index ${origIdx}`);
      }
      const newIdx = canonElems.length;
      canonElems.push(elem);
      rhsCache.set(origIdx, newIdx);
      return newIdx;
    };

    // Allocate a fresh canonical index for an image element (no deduplication)
    const allocateImage = (origIdx: number): number => {
      const elem = orig[origIdx];
      if (elem === undefined) {
        throw new Error(`Invalid element index ${origIdx}`);
      }
      const newIdx = canonElems.length;
      canonElems.push(elem);
      return newIdx;
    };

    // Process each equation, building canonical structure
    // Order: RHS terms first, then image (matches Rust processing order)
    const canonEqs: Array<{ imgIdx: number; terms: Array<[number, number]> }> = [];

    for (let eqIdx = 0; eqIdx < lm.linearCombinations.length; eqIdx++) {
      const lc = lm.linearCombinations[eqIdx];
      if (lc === undefined) {
        throw new Error(`Invalid equation index ${eqIdx}`);
      }

      // Get canonical indices for RHS term elements (with deduplication)
      const terms: Array<[number, number]> = [];
      for (let tIdx = 0; tIdx < lc.elementIndices.length; tIdx++) {
        const origElemIdx = lc.elementIndices[tIdx];
        const scalarIdx = lc.scalarIndices[tIdx];
        if (origElemIdx === undefined || scalarIdx === undefined) {
          throw new Error('Invalid term indices');
        }
        const canonIdx = getOrCreateRhs(origElemIdx);
        terms.push([scalarIdx, canonIdx]);
      }

      // Allocate fresh canonical index for image element (no deduplication)
      const origImgIdx = this.imageIndices[eqIdx];
      if (origImgIdx === undefined) {
        throw new Error(`Invalid image index for equation ${eqIdx}`);
      }
      const canonImgIdx = allocateImage(origImgIdx);

      canonEqs.push({ imgIdx: canonImgIdx, terms });
    }

    // Serialize
    const parts: Uint8Array[] = [];

    // Header: number of equations
    parts.push(u32le(canonEqs.length));

    // Each equation
    for (const eq of canonEqs) {
      parts.push(u32le(eq.imgIdx));
      parts.push(u32le(eq.terms.length));
      for (const [sIdx, gIdx] of eq.terms) {
        parts.push(u32le(sIdx));
        parts.push(u32le(gIdx));
      }
    }

    // All canonical group elements
    for (const elem of canonElems) {
      parts.push(elem.toBytes());
    }

    // Cache and return
    this._cachedInstanceLabel = concat(...parts);
    return this._cachedInstanceLabel;
  }
}
