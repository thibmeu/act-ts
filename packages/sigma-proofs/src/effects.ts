/**
 * Batched variable-base scalar multiplication.
 *
 * Algorithms that need k * Q for points Q without precomputed tables are
 * written as generators that yield every such multiplication of a round as
 * one batch. A synchronous driver runs the batch on noble; an asynchronous
 * driver hands it to the ciphersuite's native backend (WebCrypto for P-256),
 * which is several times faster and constant time. One implementation, two
 * APIs.
 */

import type { Ciphersuite, Point } from './ciphersuites.js';

/**
 * k * Q; `secret` selects a constant-time multiplication. Jobs sharing a
 * `group` are summed by their consumer, so a backend may merge those on the
 * same point into one multiplication.
 */
export type Job = readonly [point: Point, scalar: bigint, secret: boolean, group?: number];

/** A computation that yields batches of jobs and receives their results. */
export type Effect<R> = Generator<readonly Job[], R, Point[]>;

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
    if (!byPoint) merged.set(group, (byPoint = new Map()));
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

/** Runs an effect with noble only. */
export function runSync<R>(suite: Ciphersuite, effect: Effect<R>): R {
  let step = effect.next();
  while (!step.done) step = effect.next(mulManyNoble(suite, step.value));
  return step.value;
}

/** Runs an effect with the ciphersuite's native backend, if any. */
export async function runAsync<R>(suite: Ciphersuite, effect: Effect<R>): Promise<R> {
  let step = effect.next();
  while (!step.done) {
    const jobs = step.value;
    const results =
      suite.mulMany && jobs.length > 0 ? await suite.mulMany(jobs) : mulManyNoble(suite, jobs);
    step = effect.next(results);
  }
  return step.value;
}

/** Yields one batch; a helper for composing effects. */
export function* mulAll(jobs: readonly Job[]): Effect<Point[]> {
  return jobs.length === 0 ? [] : yield jobs;
}
