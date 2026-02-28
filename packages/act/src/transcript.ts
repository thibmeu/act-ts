/**
 * ACT Transcript - BLAKE3-based Fiat-Shamir Transform
 *
 * Section 3.5.2: Hash Function and Fiat-Shamir Transform
 *
 * Uses BLAKE3 to accumulate protocol messages and generate challenges.
 */

import { blake3 } from '@noble/hashes/blake3';
import { bytesToNumberLE } from '@noble/curves/utils.js';
import type { Scalar, GroupElement, SystemParams } from './types.js';
import { group, Ristretto255Scalar } from './group.js';

/**
 * Protocol version string (Section 3.5.1)
 */
export const PROTOCOL_VERSION = 'curve25519-ristretto anonymous-credits v1.0';

/**
 * Encode a value to bytes for transcript (Section 3.5.3)
 */
function encode(value: Scalar | GroupElement): Uint8Array {
  return value.toBytes();
}

/**
 * Length-prefix data with 8-byte big-endian length (Section 3.5.3)
 */
function lengthPrefixed(data: Uint8Array): Uint8Array {
  const result = new Uint8Array(8 + data.length);
  const view = new DataView(result.buffer);
  // 8-byte big-endian length prefix
  view.setBigUint64(0, BigInt(data.length), false);
  result.set(data, 8);
  return result;
}

/**
 * Convert ASCII string to bytes
 */
function asciiToBytes(str: string): Uint8Array {
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    bytes[i] = str.charCodeAt(i);
  }
  return bytes;
}

/**
 * Transcript for ACT proofs
 *
 * Accumulates messages using BLAKE3 and generates challenges.
 */
export class Transcript {
  private data: Uint8Array[];
  private finalized: boolean = false;

  /**
   * Create a new transcript with given label
   *
   * Section 3.5.2: CreateTranscript(label)
   *
   * @param label - ASCII string identifying the proof type
   * @param params - System parameters (H1-H4 included per Section 3.5.2 step 2-6)
   */
  constructor(
    label: string,
    private readonly params: SystemParams
  ) {
    this.data = [];
    // Step 2: Include protocol version
    this.data.push(lengthPrefixed(asciiToBytes(PROTOCOL_VERSION)));
    // Step 3-6: Include system parameters
    this.data.push(lengthPrefixed(encode(params.H1)));
    this.data.push(lengthPrefixed(encode(params.H2)));
    this.data.push(lengthPrefixed(encode(params.H3)));
    this.data.push(lengthPrefixed(encode(params.H4)));
    // Step 7: Include label
    this.data.push(lengthPrefixed(asciiToBytes(label)));
  }

  /**
   * Add a scalar to the transcript
   *
   * Section 3.5.2: AddToTranscript(transcript, value) for Scalar
   */
  addScalar(value: Scalar): void {
    if (this.finalized) {
      throw new Error('Transcript already finalized');
    }
    this.data.push(lengthPrefixed(encode(value)));
  }

  /**
   * Add an element to the transcript
   *
   * Section 3.5.2: AddToTranscript(transcript, value) for Element
   */
  addElement(value: GroupElement): void {
    if (this.finalized) {
      throw new Error('Transcript already finalized');
    }
    this.data.push(lengthPrefixed(encode(value)));
  }

  /**
   * Add a credit amount (as scalar) to the transcript
   */
  addCredit(amount: bigint): void {
    this.addScalar(group.scalarFromBigint(amount));
  }

  /**
   * Get the challenge scalar
   *
   * Section 3.5.2: GetChallenge(transcript)
   *
   * Steps:
   * 1. hash = transcript.hasher.output(64) // 64 bytes of output
   * 2. challenge = from_little_endian_bytes(hash) mod q
   */
  getChallenge(): Scalar {
    this.finalized = true;

    // Concatenate all data
    const totalLen = this.data.reduce((sum, arr) => sum + arr.length, 0);
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const arr of this.data) {
      combined.set(arr, offset);
      offset += arr.length;
    }

    // BLAKE3 with 64-byte XOF output
    const hash = blake3(combined, { dkLen: 64 });

    // Convert to scalar: little-endian mod q
    const value = bytesToNumberLE(hash) % group.ORDER;
    return new Ristretto255Scalar(value);
  }

  /**
   * Clone transcript for branching proofs
   */
  clone(): Transcript {
    const copy = new Transcript('', this.params);
    copy.data = [...this.data];
    copy.finalized = this.finalized;
    return copy;
  }
}

/**
 * Simplified transcript without system params (for request proof)
 *
 * Used in IssueRequest where only K is committed before params exist
 */
export class SimpleTranscript {
  private data: Uint8Array[];
  private finalized: boolean = false;

  constructor(label: string) {
    this.data = [];
    this.data.push(lengthPrefixed(asciiToBytes(PROTOCOL_VERSION)));
    this.data.push(lengthPrefixed(asciiToBytes(label)));
  }

  addScalar(value: Scalar): void {
    if (this.finalized) {
      throw new Error('Transcript already finalized');
    }
    this.data.push(lengthPrefixed(value.toBytes()));
  }

  addElement(value: GroupElement): void {
    if (this.finalized) {
      throw new Error('Transcript already finalized');
    }
    this.data.push(lengthPrefixed(value.toBytes()));
  }

  getChallenge(): Scalar {
    this.finalized = true;

    const totalLen = this.data.reduce((sum, arr) => sum + arr.length, 0);
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const arr of this.data) {
      combined.set(arr, offset);
      offset += arr.length;
    }

    const hash = blake3(combined, { dkLen: 64 });
    const value = bytesToNumberLE(hash) % group.ORDER;
    return new Ristretto255Scalar(value);
  }
}
