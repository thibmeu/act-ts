/**
 * Non-interactive Sigma protocols: draft-irtf-cfrg-sigma-protocols-03,
 * Section 5, under the SHAKE128 duplex sponge of
 * draft-irtf-cfrg-fiat-shamir-03.
 */

import { normalizeZ } from '@noble/curves/abstract/curve.js';
import { mod } from '@noble/curves/abstract/modular.js';
import { bytesToNumberBE, bytesToNumberLE } from '@noble/curves/utils.js';
import { shake128 } from '@noble/hashes/sha3.js';
import { concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import {
  type Ciphersuite,
  deserializeElement,
  deserializeScalar,
  type Point,
  SigmaError,
  serializeScalar,
} from './ciphersuites.ts';
import { type ImageTerm, LinearRelation, type Term } from './linear-relation.ts';

/** Sections 3.6 and 5.2: bind arithmetic and transcript to one instance across awaits. */
function snapshotRelation(relation: LinearRelation): LinearRelation {
  const copy = new LinearRelation({ ...relation.suite });
  copy.elements.splice(0, copy.elements.length, ...relation.elements);
  for (const { image, terms } of relation.equations) {
    copy.equations.push({
      image: image.map(([e, c]): ImageTerm => [e, c]),
      terms: terms.map(([s, e, c]): Term => [s, e, c]),
    });
  }
  return copy;
}

/** SHAKE128 rate R (fiat-shamir Section 9.1). */
const RATE = 168;
const SESSION_ID_LABEL = utf8ToBytes('irtf-cfrg-fiat-shamir/session-id');

/**
 * DS.Init(session_id) (fiat-shamir Section 3.2.1). With the XOF duplex
 * sponge, absorbing then squeezing is the XOF of the concatenation.
 */
export function spongeInit(sessionId: Uint8Array): ReturnType<typeof shake128.create> {
  if (sessionId.length !== 32) throw new SigmaError('session id must be 32 bytes');
  const xof = shake128.create();
  xof.update(sessionId);
  xof.update(new Uint8Array(RATE - 32));
  return xof;
}

/** DeriveSessionID(tag) (fiat-shamir Section 5.1). */
export function deriveSessionId(tag: string | Uint8Array): Uint8Array {
  const xof = spongeInit(SESSION_ID_LABEL);
  xof.update(typeof tag === 'string' ? utf8ToBytes(tag) : tag);
  return xof.xof(32);
}

/** DecodeField(buf, p, 1): little-endian, reduced mod p (fiat-shamir Section 4.2.3). */
export function decodeField(suite: Ciphersuite, buf: Uint8Array): bigint {
  return mod(bytesToNumberLE(buf), suite.order);
}

/** DeriveChallenge (Section 5.2), from a session id rather than a tag. */
function deriveChallenge(
  relation: LinearRelation,
  sessionId: Uint8Array,
  commitments: readonly Point[]
): bigint {
  const { suite } = relation;
  const xof = spongeInit(sessionId);
  xof.update(relation.serialize());
  if (commitments.some((c) => c.is0())) throw new SigmaError('identity commitment');
  // One batched inversion instead of one per commitment.
  for (const c of normalizeZ(suite.Point, [...commitments])) xof.update(c.toBytes(true));
  return decodeField(suite, xof.xof(suite.Ns + 16));
}

/** Uniform nonces from the system CSPRNG. */
export function randomNonces(suite: Ciphersuite, count: number): bigint[] {
  return Array.from({ length: count }, () =>
    mod(bytesToNumberBE(randomBytes(suite.Ns + 16)), suite.order)
  );
}

function checkProverInputs(
  relation: LinearRelation,
  witness: readonly bigint[],
  nonces: readonly bigint[]
): Point[] {
  const image = relation.validate();
  const n = relation.numScalars;
  if (witness.length !== n || nonces.length !== n) throw new SigmaError('wrong witness length');
  return image;
}

function responses(
  relation: LinearRelation,
  witness: readonly bigint[],
  nonces: readonly bigint[],
  challenge: bigint
): Uint8Array[] {
  const { suite } = relation;
  return nonces.map((k, i) =>
    serializeScalar(suite, mod(k + (witness[i] ?? 0n) * challenge, suite.order))
  );
}

type Openings = ReadonlyMap<number, readonly ImageTerm[]>;

/**
 * ProveCompact (Section 5.5): challenge || response.
 *
 * `nonces` are the prover's commitment randomness, one per witness scalar;
 * they default to fresh CSPRNG output and MUST never be reused. `openings` is
 * an optional prover speed-up; see {@link LinearRelation.commit}.
 */
export async function proveCompact(
  sessionId: Uint8Array,
  relation: LinearRelation,
  witness: readonly bigint[],
  nonces: readonly bigint[] = randomNonces(relation.suite, witness.length),
  openings?: Openings
): Promise<Uint8Array> {
  relation = snapshotRelation(relation);
  sessionId = sessionId.slice();
  witness = [...witness];
  nonces = [...nonces];
  checkProverInputs(relation, witness, nonces);
  const commitments = await relation.commit(nonces, openings);
  const challenge = deriveChallenge(relation, sessionId, commitments);
  return concatBytes(
    serializeScalar(relation.suite, challenge),
    ...responses(relation, witness, nonces, challenge)
  );
}

/** VerifyCompact (Section 5.5). */
export async function verifyCompact(
  sessionId: Uint8Array,
  relation: LinearRelation,
  proof: Uint8Array
): Promise<boolean> {
  try {
    relation = snapshotRelation(relation);
    sessionId = sessionId.slice();
    const { suite } = relation;
    const image = relation.validate();
    const n = relation.numScalars;
    if (proof.length !== suite.Ns * (n + 1)) return false;
    const scalars = Array.from({ length: n + 1 }, (_, i) =>
      deserializeScalar(suite, proof.subarray(i * suite.Ns, (i + 1) * suite.Ns))
    );
    const [challenge = 0n, ...response] = scalars;
    const commitments = await relation.simulate(challenge, response, image);
    // deriveChallenge rejects an identity commitment (step 7).
    return deriveChallenge(relation, sessionId, commitments) === challenge;
  } catch (e) {
    if (e instanceof SigmaError) return false;
    throw e;
  }
}

/** ProveBatchable (Section 5.4): commitment || response. */
export async function proveBatchable(
  sessionId: Uint8Array,
  relation: LinearRelation,
  witness: readonly bigint[],
  nonces: readonly bigint[] = randomNonces(relation.suite, witness.length),
  openings?: Openings
): Promise<Uint8Array> {
  relation = snapshotRelation(relation);
  sessionId = sessionId.slice();
  witness = [...witness];
  nonces = [...nonces];
  checkProverInputs(relation, witness, nonces);
  const commitments = await relation.commit(nonces, openings);
  const challenge = deriveChallenge(relation, sessionId, commitments);
  return concatBytes(
    ...normalizeZ(relation.suite.Point, commitments).map((c) => c.toBytes(true)),
    ...responses(relation, witness, nonces, challenge)
  );
}

/** VerifyBatchable (Section 5.4). */
export async function verifyBatchable(
  sessionId: Uint8Array,
  relation: LinearRelation,
  proof: Uint8Array
): Promise<boolean> {
  try {
    relation = snapshotRelation(relation);
    sessionId = sessionId.slice();
    const { suite } = relation;
    const image = relation.validate();
    const m = relation.equations.length;
    const n = relation.numScalars;
    if (proof.length !== suite.Ne * m + suite.Ns * n) return false;
    const commitments = Array.from({ length: m }, (_, i) =>
      deserializeElement(suite, proof.subarray(i * suite.Ne, (i + 1) * suite.Ne))
    );
    const base = suite.Ne * m;
    const response = Array.from({ length: n }, (_, i) =>
      deserializeScalar(suite, proof.subarray(base + i * suite.Ns, base + (i + 1) * suite.Ns))
    );
    const challenge = deriveChallenge(relation, sessionId, commitments);
    const expected = await relation.simulate(challenge, response, image);
    return expected.every((p, i) => {
      const c = commitments[i];
      return c !== undefined && p.equals(c);
    });
  } catch (e) {
    if (e instanceof SigmaError) return false;
    throw e;
  }
}
