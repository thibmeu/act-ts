/**
 * Helper functions for common sigma protocol patterns.
 *
 * These helpers append standard proof structures to a LinearRelation,
 * following the patterns from draft-act (sigma-draft-compliance branch).
 */

import type { GroupElement } from './group.js';
import type { LinearRelation } from './linear-relation.js';

/**
 * Append a Pedersen commitment proof to a relation.
 *
 * Proves knowledge of scalars (a, b) such that:
 *   R = a*P + b*Q
 *
 * @param relation - The LinearRelation to append to
 * @param P - First base point (element index)
 * @param Q - Second base point (element index)
 * @param R - Commitment point (element index, becomes image)
 * @param a - First scalar (scalar index)
 * @param b - Second scalar (scalar index)
 */
export function appendPedersen(
  relation: LinearRelation,
  P: number,
  Q: number,
  R: number,
  a: number,
  b: number
): void {
  relation.appendEquation(R, [
    [a, P],
    [b, Q],
  ]);
}

/**
 * Append a DLEQ (discrete log equality) proof to a relation.
 *
 * Proves knowledge of scalar x such that:
 *   X = x*P  AND  Y = x*Q
 *
 * This appends TWO equations to the relation.
 *
 * @param relation - The LinearRelation to append to
 * @param P - First base point (element index)
 * @param Q - Second base point (element index)
 * @param X - First result point (element index, becomes image)
 * @param Y - Second result point (element index, becomes image)
 * @param x - Scalar witness (scalar index)
 */
export function appendDleq(
  relation: LinearRelation,
  P: number,
  Q: number,
  X: number,
  Y: number,
  x: number
): void {
  // X = x*P
  relation.appendEquation(X, [[x, P]]);
  // Y = x*Q
  relation.appendEquation(Y, [[x, Q]]);
}

/**
 * Append a range proof to a relation using algebraic binary constraints.
 *
 * For each bit j in [0, L), proves:
 *   1. Opening: Com[j] = b[j]*H1 + s[j]*H3  (+ kstar*H2 for j=0)
 *   2. Binary constraint: Com[j] = b[j]*Com[j] + s2[j]*H3
 *
 * The binary constraint enforces b[j] ∈ {0, 1}:
 * - If b[j] = 0: Com[j] = s2[j]*H3, so s2[j] = s[j] works
 * - If b[j] = 1: Com[j] = Com[j] + s2[j]*H3, so s2[j] = 0 works
 * - If b[j] ≥ 2: No valid s2[j] exists (requires knowing DLOG between H1 and H3)
 *
 * This appends 2*L equations to the relation.
 *
 * @param relation - The LinearRelation to append to
 * @param H1 - Bit value generator (element index)
 * @param H2 - Nullifier generator (element index) - used in Com[0] only
 * @param H3 - Blinding generator (element index)
 * @param Com - Array of L commitment element indices
 * @param b - Array of L bit scalar indices
 * @param sCom - Array of L blinding scalar indices
 * @param s2 - Array of L derived scalar indices for binary constraint
 * @param kStar - Nullifier scalar index (used in Com[0])
 */
export function appendRangeProof(
  relation: LinearRelation,
  H1: number,
  H2: number,
  H3: number,
  Com: readonly number[],
  b: readonly number[],
  sCom: readonly number[],
  s2: readonly number[],
  kStar: number
): void {
  const L = Com.length;
  if (b.length !== L || sCom.length !== L || s2.length !== L) {
    throw new Error('Range proof arrays must all have length L');
  }

  for (let j = 0; j < L; j++) {
    const comJ = Com[j];
    const bJ = b[j];
    const sComJ = sCom[j];
    const s2J = s2[j];

    if (comJ === undefined || bJ === undefined || sComJ === undefined || s2J === undefined) {
      throw new Error(`Invalid index ${j} in range proof arrays`);
    }

    // Equation 1: Opening proof
    // Com[j] = b[j]*H1 + s[j]*H3  (+ kstar*H2 for j=0)
    if (j === 0) {
      relation.appendEquation(comJ, [
        [bJ, H1],
        [kStar, H2],
        [sComJ, H3],
      ]);
    } else {
      relation.appendEquation(comJ, [
        [bJ, H1],
        [sComJ, H3],
      ]);
    }

    // Equation 2: Binary constraint
    // Com[j] = b[j]*Com[j] + s2[j]*H3
    relation.appendEquation(comJ, [
      [bJ, comJ],
      [s2J, H3],
    ]);
  }
}

/**
 * Setup elements for a range proof, allocating Com elements.
 *
 * This is a convenience function that:
 * 1. Allocates L commitment element slots
 * 2. Sets them with the provided commitment values
 *
 * @param relation - The LinearRelation
 * @param commitments - Array of L commitment elements
 * @returns Array of allocated element indices for Com
 */
export function setupRangeProofElements(
  relation: LinearRelation,
  commitments: readonly GroupElement[]
): number[] {
  const L = commitments.length;
  const comIndices = relation.allocateElements(L);

  const elementPairs: Array<[number, GroupElement]> = [];
  for (let j = 0; j < L; j++) {
    const idx = comIndices[j];
    const elem = commitments[j];
    if (idx === undefined || elem === undefined) {
      throw new Error(`Invalid index ${j} in setupRangeProofElements`);
    }
    elementPairs.push([idx, elem]);
  }
  relation.setElements(elementPairs);

  return comIndices;
}
