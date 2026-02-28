/**
 * Schnorr-style sigma protocol for linear relations.
 *
 * Implements Section 2.2.4-2.2.6 of draft-irtf-cfrg-sigma-protocols-01.
 */

import type { GroupElement, Scalar } from './group.js';
import type { LinearRelation } from './linear-relation.js';

/** Commitment message (array of group elements) */
export type Commitment = readonly GroupElement[];

/** Response message (array of scalars) */
export type Response = readonly Scalar[];

/**
 * Result of prover commitment phase.
 *
 * Contains the commitment to send to verifier, and a one-shot `respond`
 * function that computes the response given a challenge.
 *
 * ��️ SECURITY: The `respond` function captures secret material (witness, nonces).
 * - Call `respond` exactly once, then discard this object
 * - Do not persist, serialize, or log
 * - JavaScript cannot guarantee memory zeroization
 */
export interface ProverCommitment {
  /** The commitment to send to the verifier */
  readonly commitment: Commitment;
  /**
   * Compute the response for the given challenge.
   *
   * ⚠️ This function can only be called ONCE. Subsequent calls throw an error
   * to prevent nonce reuse, which would leak the witness.
   *
   * @param challenge - Challenge scalar from verifier
   * @returns Response (array of scalars)
   * @throws If called more than once
   */
  respond(challenge: Scalar): Response;
}

/**
 * Schnorr proof protocol for proving knowledge of a preimage under a linear map.
 */
export class SchnorrProof {
  readonly relation: LinearRelation;

  constructor(relation: LinearRelation) {
    this.relation = relation;
  }

  /**
   * Prover commitment phase.
   *
   * Generates the commitment and returns a one-shot respond function.
   * The respond function can only be called once to prevent nonce reuse.
   *
   * @param witness - The secret witness (array of scalars)
   * @returns ProverCommitment with commitment and respond function
   */
  proverCommit(witness: Scalar[]): ProverCommitment {
    if (witness.length !== this.relation.numScalars) {
      throw new Error(
        `Witness length ${witness.length} does not match expected ${this.relation.numScalars}`
      );
    }

    // Generate random nonces
    const nonces: Scalar[] = [];
    for (let i = 0; i < this.relation.numScalars; i++) {
      nonces.push(this.relation.group.randomScalar());
    }

    // Compute commitment: linearMap(nonces)
    const commitment = this.relation.linearMap.map(nonces);

    // Track if respond has been called
    let consumed = false;

    return {
      commitment,
      respond: (challenge: Scalar): Response => {
        if (consumed) {
          throw new Error(
            'ProverCommitment.respond() already called - cannot reuse (nonce reuse leaks witness)'
          );
        }
        consumed = true;

        // response[i] = nonces[i] + witness[i] * challenge
        const response: Scalar[] = [];
        for (let i = 0; i < nonces.length; i++) {
          const n = nonces[i];
          const w = witness[i];
          if (n === undefined || w === undefined) {
            throw new Error('Invalid prover state');
          }
          response.push(n.add(w.mul(challenge)));
        }
        return response;
      },
    };
  }

  /**
   * Verifier algorithm.
   *
   * Checks that the protocol transcript is valid.
   *
   * @param commitment - Commitment from prover
   * @param challenge - Challenge scalar
   * @param response - Response from prover
   * @returns true if verification succeeds
   */
  verify(commitment: Commitment, challenge: Scalar, response: Response): boolean {
    if (commitment.length !== this.relation.numConstraints) {
      return false;
    }
    if (response.length !== this.relation.numScalars) {
      return false;
    }

    // expected = linearMap(response)
    const expected = this.relation.linearMap.map(response as Scalar[]);

    // got[i] = commitment[i] + image[i] * challenge
    for (let i = 0; i < this.relation.numConstraints; i++) {
      const commitI = commitment[i];
      const imageI = this.relation.image[i];
      const expectedI = expected[i];

      if (commitI === undefined || imageI === undefined || expectedI === undefined) {
        return false;
      }

      const got = commitI.add(imageI.multiply(challenge));
      if (!got.equals(expectedI)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Serialize commitment to bytes.
   */
  serializeCommitment(commitment: Commitment): Uint8Array {
    const parts: Uint8Array[] = commitment.map((e) => e.toBytes());
    const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const p of parts) {
      result.set(p, offset);
      offset += p.length;
    }
    return result;
  }

  /**
   * Serialize response to bytes.
   */
  serializeResponse(response: Response): Uint8Array {
    const parts: Uint8Array[] = response.map((s) => s.toBytes());
    const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const p of parts) {
      result.set(p, offset);
      offset += p.length;
    }
    return result;
  }

  /**
   * Deserialize commitment from bytes.
   */
  deserializeCommitment(data: Uint8Array): Commitment {
    const elementSize = this.relation.group.elementSize;
    if (data.length !== this.relation.numConstraints * elementSize) {
      throw new Error('Invalid commitment length');
    }

    const commitment: GroupElement[] = [];
    for (let i = 0; i < this.relation.numConstraints; i++) {
      const slice = data.slice(i * elementSize, (i + 1) * elementSize);
      commitment.push(this.relation.group.elementFromBytes(slice));
    }
    return commitment;
  }

  /**
   * Deserialize response from bytes.
   */
  deserializeResponse(data: Uint8Array): Response {
    const scalarSize = this.relation.group.scalarSize;
    if (data.length !== this.relation.numScalars * scalarSize) {
      throw new Error('Invalid response length');
    }

    const response: Scalar[] = [];
    for (let i = 0; i < this.relation.numScalars; i++) {
      const slice = data.slice(i * scalarSize, (i + 1) * scalarSize);
      response.push(this.relation.group.scalarFromBytes(slice));
    }
    return response;
  }

  // ============================================================
  // Simulator functions (for OR-composition and short proofs)
  // See draft-irtf-cfrg-sigma-protocols-01 Section 1.1
  // ============================================================

  /**
   * Simulate a response without knowing the witness.
   *
   * Used for:
   * - OR-composition: simulate non-taken branches
   * - Zero-knowledge simulators
   *
   * @returns Simulated response (random scalars)
   */
  simulateResponse(): Response {
    const response: Scalar[] = [];
    for (let i = 0; i < this.relation.numScalars; i++) {
      response.push(this.relation.group.randomScalar());
    }
    return response;
  }

  /**
   * Compute commitment from a simulated response and challenge.
   *
   * Given a simulated (response, challenge), compute the commitment
   * that would make the transcript valid.
   *
   * Used for:
   * - OR-composition: compute commitment for simulated branch
   * - "Short proofs" verification (recompute commitment from response)
   *
   * The commitment is computed as:
   *   commitment[i] = linearMap(response)[i] - image[i] * challenge
   *
   * @param response - Simulated response
   * @param challenge - Challenge scalar
   * @returns Simulated commitment
   */
  simulateCommitment(response: Response, challenge: Scalar): Commitment {
    if (response.length !== this.relation.numScalars) {
      throw new Error(
        `Response length ${response.length} does not match expected ${this.relation.numScalars}`
      );
    }

    // linearMap(response)
    const lhs = this.relation.linearMap.map(response as Scalar[]);

    // commitment[i] = lhs[i] - image[i] * challenge
    const commitment: GroupElement[] = [];
    for (let i = 0; i < this.relation.numConstraints; i++) {
      const lhsI = lhs[i];
      const imageI = this.relation.image[i];
      if (lhsI === undefined || imageI === undefined) {
        throw new Error('Invalid relation state');
      }
      // commitment = lhs - image * challenge
      // Since we don't have subtract on GroupElement, use: lhs + (image * -challenge)
      const negChallenge = challenge.neg();
      commitment.push(lhsI.add(imageI.multiply(negChallenge)));
    }

    return commitment;
  }

  /**
   * Simulate a complete proof transcript without knowing the witness.
   *
   * This is the zero-knowledge simulator: given only the public
   * statement and a challenge, produce a valid-looking transcript.
   *
   * @param challenge - Challenge to use (or random if not provided)
   * @returns Tuple of [commitment, response]
   */
  simulate(challenge?: Scalar): [Commitment, Response] {
    const c = challenge ?? this.relation.group.randomScalar();
    const response = this.simulateResponse();
    const commitment = this.simulateCommitment(response, c);
    return [commitment, response];
  }
}
