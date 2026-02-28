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

/** Maximum number of scalars to prevent DoS */
const MAX_SCALARS = 1024;
/** Maximum number of elements to prevent DoS */
const MAX_ELEMENTS = 1024;

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
 * ```
 */
export class LinearRelation {
  readonly linearMap: LinearMap;
  readonly image: GroupElement[] = [];

  constructor(group: Group) {
    this.linearMap = new LinearMap(group);
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
    const lc: LinearCombination = {
      scalarIndices: rhs.map(([s, _]) => s),
      elementIndices: rhs.map(([_, e]) => e),
    };

    this.linearMap.append(lc);

    // The image will be set later via setElements for lhs
    // For now, push identity as placeholder
    this.image.push(this.linearMap.group.identity());
  }

  /**
   * Set concrete values for allocated group elements.
   *
   * @param elements - Array of [index, element] pairs
   */
  setElements(elements: Array<[number, GroupElement]>): void {
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
   * Set the image values (left-hand sides of equations).
   *
   * @param images - Array of [constraintIndex, element] pairs
   */
  setImage(images: Array<[number, GroupElement]>): void {
    for (const [index, element] of images) {
      if (index < 0 || index >= this.image.length) {
        throw new Error(`Image index ${index} out of bounds (valid: 0-${this.image.length - 1})`);
      }
      this.image[index] = element;
    }
  }
}
