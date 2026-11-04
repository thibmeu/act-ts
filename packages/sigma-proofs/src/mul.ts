/**
 * Batched scalar multiplication.
 *
 * Provers and verifiers collect every scalar multiplication of a round into
 * one batch, which the ciphersuite's native backend (WebCrypto for P-256)
 * runs several times faster than noble, and in constant time. Without one,
 * noble runs the batch.
 */

import type { Ciphersuite, Point } from './ciphersuites.ts';

/**
 * k * Q; `secret` selects a constant-time multiplication. Jobs sharing a
 * `group` are summed by their consumer, so a backend may merge those on the
 * same point into one multiplication.
 */
export type Job = readonly [point: Point, scalar: bigint, secret: boolean, group?: number];

/**
 * k * P for k in [0, p). noble's constant-time multiply rejects zero, so
 * compute (k + 1) * P - P; only k = p - 1, of negligible probability for a
 * secret, takes another path.
 */
export function mulCt(P: Point, k: bigint, p: bigint): Point {
  return k === p - 1n ? P.negate() : P.multiply(k + 1n).subtract(P);
}

/** Runs one job on noble. */
export function mulNoble(suite: Ciphersuite, [P, k, secret]: Job): Point {
  return secret ? mulCt(P, k, suite.order) : P.multiplyUnsafe(k);
}

/**
 * Runs a batch on noble, merging grouped jobs on the same point: the first
 * gets the product of the summed scalar, the others the identity.
 */
export function mulManyNoble(suite: Ciphersuite, jobs: readonly Job[]): Point[] {
  const merged = new Map<number, Map<Point, number>>();
  const scalars = jobs.map(([, k]) => k);
  const lead = jobs.map((job, i) => {
    const [P, k, , group] = job;
    if (group === undefined) return i;
    let byPoint = merged.get(group);
    if (!byPoint) {
      byPoint = new Map();
      merged.set(group, byPoint);
    }
    const first = byPoint.get(P);
    if (first === undefined) {
      byPoint.set(P, i);
      return i;
    }
    scalars[first] = ((scalars[first] ?? 0n) + k) % suite.order;
    return first;
  });
  return jobs.map(([P, , secret], i) =>
    lead[i] === i ? mulNoble(suite, [P, scalars[i] ?? 0n, secret]) : suite.Point.ZERO
  );
}

/** Runs a batch on the ciphersuite's native backend, or on noble. */
export async function mulMany(suite: Ciphersuite, jobs: readonly Job[]): Promise<Point[]> {
  if (jobs.length === 0) return [];
  return (await suite.mulMany?.(jobs)) ?? mulManyNoble(suite, jobs);
}
