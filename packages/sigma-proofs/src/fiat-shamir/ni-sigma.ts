/**
 * Non-interactive sigma protocol via Fiat-Shamir transformation.
 *
 * Implements Section 5 of draft-irtf-cfrg-fiat-shamir-01.
 */

import type { Group, GroupElement, Scalar } from '../group.js';
import type { LinearRelation } from '../linear-relation.js';
import { SchnorrProof } from '../schnorr.js';
import { asciiToBytes } from '../utils.js';
import { Shake128Sponge, type DuplexSponge } from './sponge.js';
import { ByteCodec, type Codec } from './codec.js';

/**
 * Options for proof generation/verification.
 */
export interface NIOptions {
  /** Session identifier for domain separation */
  sessionId?: Uint8Array;
}

/**
 * A non-interactive proof in challenge-response format.
 */
export interface NIProof {
  /** The Fiat-Shamir challenge */
  challenge: Scalar;
  /** The prover's response */
  response: readonly Scalar[];
}

/**
 * A non-interactive proof in batchable (commitment-response) format.
 */
export interface NIProofBatchable {
  /** The commitment elements */
  commitment: readonly GroupElement[];
  /** The prover's response */
  response: readonly Scalar[];
}

/**
 * Concatenate Uint8Arrays.
 */
function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * I2OSP: Integer to Octet String Primitive (RFC 8017).
 * Encodes as big-endian.
 */
function i2osp(value: number, length: number): Uint8Array {
  const result = new Uint8Array(length);
  const view = new DataView(result.buffer);
  if (length === 4) {
    view.setUint32(0, value, false); // big-endian
  } else if (length === 2) {
    view.setUint16(0, value, false);
  } else {
    // Fallback for other lengths
    for (let i = length - 1; i >= 0 && value > 0; i--) {
      result[i] = value & 0xff;
      value >>>= 8;
    }
  }
  return result;
}

/**
 * Default protocol ID matching sigma-rs/sigma-hs.
 * "ietf sigma proof linear relation" + 32 zero bytes = 64 bytes total
 */
const DEFAULT_PROTOCOL_ID = (() => {
  const prefix = asciiToBytes('ietf sigma proof linear relation');
  const result = new Uint8Array(64);
  result.set(prefix);
  // Rest is zeros
  return result;
})();

/**
 * Initialize a Fiat-Shamir sponge per sigma-rs/sigma-hs.
 *
 * 1. Use protocolId directly as the sponge IV
 * 2. Absorb length-prefixed sessionId
 * 3. Absorb length-prefixed instanceLabel
 *
 * @param protocolId - Protocol identifier (64 bytes)
 * @param sessionId - Session identifier
 * @param instanceLabel - Canonical instance label from LinearRelation
 */
function initializeSponge(
  protocolId: Uint8Array,
  sessionId: Uint8Array,
  instanceLabel: Uint8Array
): Shake128Sponge {
  const sponge = new Shake128Sponge(protocolId);
  // Absorb length-prefixed session ID (big-endian length per sigma-hs)
  sponge.absorb(concat(i2osp(sessionId.length, 4), sessionId));
  // Absorb length-prefixed instance label
  sponge.absorb(concat(i2osp(instanceLabel.length, 4), instanceLabel));
  return sponge;
}

/**
 * Non-interactive Schnorr proof using Fiat-Shamir transformation.
 *
 * Section 5 of draft-irtf-cfrg-fiat-shamir-01.
 */
export class NISigmaProtocol {
  private readonly group: Group;
  private readonly relation: LinearRelation;
  private readonly sigma: SchnorrProof;
  private readonly codec: Codec;

  /**
   * Create a non-interactive sigma protocol instance.
   *
   * @param relation - The linear relation to prove
   * @param options - Session configuration
   */
  constructor(relation: LinearRelation, options: NIOptions = {}) {
    this.relation = relation;
    this.group = relation.group;
    this.sigma = new SchnorrProof(relation);

    const sessionId = options.sessionId ?? new Uint8Array(0);
    const instanceLabel = relation.getInstanceLabel();

    const sponge = initializeSponge(DEFAULT_PROTOCOL_ID, sessionId, instanceLabel);
    this.codec = new ByteCodec(this.group, sponge);
  }

  /**
   * Generate a non-interactive proof in challenge-response format.
   *
   * This is the standard format where proof = (challenge, response).
   * The verifier recomputes the commitment from the challenge and response.
   *
   * @param witness - The secret witness values
   * @returns The non-interactive proof
   */
  prove(witness: readonly Scalar[]): NIProof {
    // Step 1: Generate commitment
    const prover = this.sigma.proverCommit(witness as Scalar[]);

    // Step 2: Absorb commitment into hash state
    const codec = this.codec.clone();
    codec.absorbElements(prover.commitment);

    // Step 3: Squeeze challenge
    const challenge = codec.squeezeChallenge();

    // Step 4: Compute response
    const response = prover.respond(challenge);

    return { challenge, response };
  }

  /**
   * Verify a non-interactive proof in challenge-response format.
   *
   * @param proof - The proof to verify
   * @returns True if the proof is valid
   */
  verify(proof: NIProof): boolean {
    // Step 1: Recompute commitment from challenge and response
    const commitment = this.sigma.simulateCommitment(proof.response, proof.challenge);

    // Step 2: Absorb commitment into hash state
    const codec = this.codec.clone();
    codec.absorbElements(commitment);

    // Step 3: Squeeze challenge and compare
    const expectedChallenge = codec.squeezeChallenge();

    // Step 4: Verify challenge matches
    return proof.challenge.equals(expectedChallenge);
  }

  /**
   * Generate a non-interactive proof in batchable (commitment-response) format.
   *
   * This format includes the commitment explicitly, allowing for batch verification.
   *
   * @param witness - The secret witness values
   * @returns The batchable proof
   */
  proveBatchable(witness: readonly Scalar[]): NIProofBatchable {
    // Step 1: Generate commitment
    const prover = this.sigma.proverCommit(witness as Scalar[]);

    // Step 2: Absorb commitment and get challenge
    const codec = this.codec.clone();
    codec.absorbElements(prover.commitment);
    const challenge = codec.squeezeChallenge();

    // Step 3: Compute response
    const response = prover.respond(challenge);

    return { commitment: prover.commitment, response };
  }

  /**
   * Verify a non-interactive proof in batchable format.
   *
   * @param proof - The batchable proof to verify
   * @returns True if the proof is valid
   */
  verifyBatchable(proof: NIProofBatchable): boolean {
    // Step 1: Absorb commitment into hash state
    const codec = this.codec.clone();
    codec.absorbElements(proof.commitment);

    // Step 2: Squeeze challenge
    const challenge = codec.squeezeChallenge();

    // Step 3: Run sigma protocol verifier
    return this.sigma.verify(proof.commitment, challenge, proof.response);
  }

  /**
   * Serialize a challenge-response proof to bytes.
   */
  serializeProof(proof: NIProof): Uint8Array {
    const parts: Uint8Array[] = [proof.challenge.toBytes()];
    for (const r of proof.response) {
      parts.push(r.toBytes());
    }
    return concat(...parts);
  }

  /**
   * Deserialize a challenge-response proof from bytes.
   */
  deserializeProof(bytes: Uint8Array): NIProof {
    const scalarSize = this.group.scalarSize;
    const responseLen = this.relation.numScalars;
    const expectedLen = scalarSize * (1 + responseLen);

    if (bytes.length !== expectedLen) {
      throw new Error(`Invalid proof length: expected ${expectedLen}, got ${bytes.length}`);
    }

    const challenge = this.group.scalarFromBytes(bytes.subarray(0, scalarSize));
    const response: Scalar[] = [];
    for (let i = 0; i < responseLen; i++) {
      const start = scalarSize * (1 + i);
      response.push(this.group.scalarFromBytes(bytes.subarray(start, start + scalarSize)));
    }

    return { challenge, response };
  }

  /**
   * Serialize a batchable proof to bytes.
   */
  serializeBatchableProof(proof: NIProofBatchable): Uint8Array {
    const parts: Uint8Array[] = [];
    for (const c of proof.commitment) {
      parts.push(c.toBytes());
    }
    for (const r of proof.response) {
      parts.push(r.toBytes());
    }
    return concat(...parts);
  }

  /**
   * Deserialize a batchable proof from bytes.
   */
  deserializeBatchableProof(bytes: Uint8Array): NIProofBatchable {
    const elementSize = this.group.elementSize;
    const scalarSize = this.group.scalarSize;
    const commitLen = this.relation.numConstraints;
    const responseLen = this.relation.numScalars;
    const expectedLen = elementSize * commitLen + scalarSize * responseLen;

    if (bytes.length !== expectedLen) {
      throw new Error(`Invalid proof length: expected ${expectedLen}, got ${bytes.length}`);
    }

    const commitment: GroupElement[] = [];
    for (let i = 0; i < commitLen; i++) {
      const start = elementSize * i;
      commitment.push(this.group.elementFromBytes(bytes.subarray(start, start + elementSize)));
    }

    const response: Scalar[] = [];
    const responseStart = elementSize * commitLen;
    for (let i = 0; i < responseLen; i++) {
      const start = responseStart + scalarSize * i;
      response.push(this.group.scalarFromBytes(bytes.subarray(start, start + scalarSize)));
    }

    return { commitment, response };
  }
}
