/**
 * ACT System Parameters Generation
 *
 * Section 3.1: SetGenerators
 *
 * Generates H1, H2, H3, H4 using hash-to-group with counter for collision avoidance.
 * Uses SHAKE128 per the new draft (replacing BLAKE3).
 */

import { shake128 } from '@noble/hashes/sha3.js';
import type { Group, GroupElement } from 'sigma-proofs';
import { ACTError, ACTErrorCode } from './errors.js';
import { toHex } from './rng.js';

/**
 * System parameters (Section 3.1 of ACT draft)
 *
 * - G: Generator of the Ristretto group (implicit, from group)
 * - H1, H2, H3, H4: Additional generators for commitments
 * - L: Bit length for credit values (1 <= L <= 128)
 * - domainSeparator: Unique deployment identifier
 */
export interface SystemParams {
  readonly group: Group;
  readonly H1: GroupElement;
  readonly H2: GroupElement;
  readonly H3: GroupElement;
  readonly H4: GroupElement;
  readonly L: number;
  readonly domainSeparator: Uint8Array;
}

/**
 * Concatenate Uint8Arrays
 */
function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
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
 * Encode counter as single byte (u8)
 * Matches Rust implementation which uses [counter] as a single byte array
 */
function u8(value: number): Uint8Array {
  if (value < 0 || value > 255) {
    throw new ACTError(`Counter value out of range: ${value}`, ACTErrorCode.InvalidParameter);
  }
  return new Uint8Array([value]);
}

/**
 * SetGenerators (Section 3.1 of new draft)
 *
 * Generates H1, H2, H3, H4 deterministically from domain_separator.
 * Uses hash-to-group with distinct prefixes and collision-avoidance counter.
 *
 * Algorithm:
 * ```
 * ctr = 0
 * repeat:
 *   H1 = G.HashToGroup("GenH1" || ctr || domain_separator)
 *   H2 = G.HashToGroup("GenH2" || ctr || domain_separator)
 *   H3 = G.HashToGroup("GenH3" || ctr || domain_separator)
 *   H4 = G.HashToGroup("GenH4" || ctr || domain_separator)
 *   ctr++
 * until len({G0, H1, H2, H3, H4}) == 5  // all distinct
 * ```
 *
 * @param group - The elliptic curve group
 * @param domainSeparator - Unique deployment identifier (bytes)
 * @returns Tuple [H1, H2, H3, H4]
 */
export function setGenerators(
  group: Group,
  domainSeparator: Uint8Array
): [GroupElement, GroupElement, GroupElement, GroupElement] {
  const G0 = group.generator();
  const maxIterations = 256; // Prevent infinite loop (collision extremely unlikely)

  for (let ctr = 0; ctr < maxIterations; ctr++) {
    const ctrBytes = u8(ctr);

    // DST for hash-to-group per ACT(ristretto255, SHAKE128) suite
    // Must match Rust: format!("HashToGroup-{}", domain_separator)
    const dst = concat(asciiToBytes('HashToGroup-'), domainSeparator);

    // Generate candidates - msg format: "GenHN" || counter || domain_separator
    // Uses hash_to_ristretto255(msg, dst) internally
    const H1 = group.hashToElement(concat(asciiToBytes('GenH1'), ctrBytes, domainSeparator), dst);
    const H2 = group.hashToElement(concat(asciiToBytes('GenH2'), ctrBytes, domainSeparator), dst);
    const H3 = group.hashToElement(concat(asciiToBytes('GenH3'), ctrBytes, domainSeparator), dst);
    const H4 = group.hashToElement(concat(asciiToBytes('GenH4'), ctrBytes, domainSeparator), dst);

    // Check all 5 are distinct (set accumulator approach per armfazh suggestion)
    const elements = [G0, H1, H2, H3, H4];
    const serialized = new Set(elements.map((e) => toHex(e.toBytes())));

    if (serialized.size === 5) {
      return [H1, H2, H3, H4];
    }
  }

  throw new ACTError(
    'Failed to generate distinct generators (collision detected)',
    ACTErrorCode.InvalidParameter
  );
}

/**
 * GenerateParameters (Section 3.1)
 *
 * Generates complete system parameters from a domain separator.
 *
 * @param group - The elliptic curve group (ristretto255)
 * @param domainSeparator - Unique identifier (string or bytes)
 * @param L - Bit length for credit values (1 <= L <= 128)
 * @returns System parameters
 */
export function generateParameters(
  group: Group,
  domainSeparator: string | Uint8Array,
  L: number = 64
): SystemParams {
  // Validate L constraint
  if (L < 1 || L > 128) {
    throw new ACTError(`L must be in range [1, 128], got ${L}`, ACTErrorCode.InvalidParameter);
  }

  const domainBytes =
    typeof domainSeparator === 'string' ? asciiToBytes(domainSeparator) : domainSeparator;

  const [H1, H2, H3, H4] = setGenerators(group, domainBytes);

  return {
    group,
    H1,
    H2,
    H3,
    H4,
    L,
    domainSeparator: domainBytes,
  };
}

/**
 * Validate a domain separator string.
 *
 * Recommended format: "ACT-v1:organization:service:deployment:version"
 */
export function validateDomainSeparator(domainSeparator: string): boolean {
  const parts = domainSeparator.split(':');

  if (parts.length < 5) {
    return false;
  }

  if (parts[0] !== 'ACT-v1') {
    return false;
  }

  // No empty components
  for (const part of parts) {
    if (part.length === 0) {
      return false;
    }
  }

  return true;
}

/**
 * Create a properly formatted domain separator.
 *
 * @param organization - Organization identifier (no colons)
 * @param service - Service name (no colons)
 * @param deploymentId - Deployment environment (no colons)
 * @param version - Version string, e.g., YYYY-MM-DD (no colons)
 */
export function createDomainSeparator(
  organization: string,
  service: string,
  deploymentId: string,
  version: string
): string {
  for (const part of [organization, service, deploymentId, version]) {
    if (part.includes(':')) {
      throw new ACTError(
        `Domain separator component cannot contain colons: "${part}"`,
        ACTErrorCode.InvalidParameter
      );
    }
    if (part.length === 0) {
      throw new ACTError(
        'Domain separator components cannot be empty',
        ACTErrorCode.InvalidParameter
      );
    }
  }

  return `ACT-v1:${organization}:${service}:${deploymentId}:${version}`;
}
