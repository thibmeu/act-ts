/**
 * Linear map representation for sigma protocols.
 *
 * Implements Section 2.2.2 of draft-irtf-cfrg-sigma-protocols-01.
 * Uses Yale sparse matrix format for efficient storage.
 */

import type { Group, GroupElement, Scalar } from './group.js';

/**
 * A linear combination representing one row of the linear map matrix.
 * Each entry (scalar_index, element_index) means: scalars[scalar_index] * elements[element_index]
 */
export interface LinearCombination {
  /** Indices into the witness (scalars) array */
  scalarIndices: number[];
  /** Indices into the group elements array */
  elementIndices: number[];
}

/**
 * A linear map from scalars to group elements.
 *
 * Represents a matrix M where computing map(scalars) returns:
 *   [sum(scalars[lc.scalarIndices[j]] * elements[lc.elementIndices[j]]) for lc in linearCombinations]
 */
export class LinearMap {
  readonly group: Group;
  readonly linearCombinations: LinearCombination[] = [];
  readonly groupElements: GroupElement[] = [];
  numScalars = 0;

  constructor(group: Group) {
    this.group = group;
  }

  /** Number of constraints (output elements) */
  get numConstraints(): number {
    return this.linearCombinations.length;
  }

  /**
   * Evaluate the linear map on a witness.
   *
   * @param scalars - The witness vector (length must equal numScalars)
   * @returns Array of group elements (length equals numConstraints)
   */
  map(scalars: readonly Scalar[]): GroupElement[] {
    if (scalars.length !== this.numScalars) {
      throw new Error(`Expected ${this.numScalars} scalars, got ${scalars.length}`);
    }

    const image: GroupElement[] = [];

    for (const lc of this.linearCombinations) {
      const coefficients: Scalar[] = [];
      const elements: GroupElement[] = [];

      for (let j = 0; j < lc.scalarIndices.length; j++) {
        const scalarIdx = lc.scalarIndices[j];
        const elementIdx = lc.elementIndices[j];

        if (scalarIdx === undefined || elementIdx === undefined) {
          throw new Error('Invalid linear combination indices');
        }

        const scalar = scalars[scalarIdx];
        const element = this.groupElements[elementIdx];

        if (scalar === undefined || element === undefined) {
          throw new Error('Index out of bounds in linear combination');
        }

        coefficients.push(scalar);
        elements.push(element);
      }

      image.push(this.group.msm(coefficients, elements));
    }

    return image;
  }

  /**
   * Append a linear combination to the map.
   */
  append(lc: LinearCombination): void {
    this.linearCombinations.push(lc);
  }
}
