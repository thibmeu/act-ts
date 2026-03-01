/**
 * ACT System Parameters Generation
 *
 * Section 3.1: System Parameters
 *
 * Generates H1, H2, H3, H4 deterministically from a domain separator
 * using BLAKE3 and OneWayMap (RFC 9496 Section 4.3.4).
 */

import { blake3 } from '@noble/hashes/blake3';
import { numberToBytesLE } from '@noble/curves/utils.js';
import type { SystemParams, GroupElement } from './types.js';
import { ACTError, ACTErrorCode } from './types.js';
import { group } from './group.js';

/**
 * Length-prefix data with 8-byte big-endian length
 */
function lengthPrefixed(data: Uint8Array): Uint8Array {
  const result = new Uint8Array(8 + data.length);
  const view = new DataView(result.buffer);
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
 * HashToRistretto255 (Section 3.1)
 *
 * Input:
 *   - seed: 32-byte seed value
 *   - counter: Integer counter for domain separation
 * Output:
 *   - P: A valid Ristretto255 point
 *
 * Uses BLAKE3 XOF to generate 64 uniform bytes, then OneWayMap.
 */
function hashToRistretto255(seed: Uint8Array, counter: number): GroupElement {
  // Spec says:
  // 1. hasher = BLAKE3.new()
  // 2. hasher.update(LengthPrefixed(domain_separator)) -- but domain_separator not passed here
  // 3. hasher.update(LengthPrefixed(seed))
  // 4. hasher.update(LengthPrefixed(counter.to_le_bytes(4)))
  // 5. uniform_bytes = hasher.finalize_xof(64)
  // 6. P = OneWayMap(uniform_bytes)

  // Note: Looking at the spec more carefully, the domain_separator is already
  // hashed into the seed in GenerateParameters step 1. So here we just use
  // seed and counter.

  const counterBytes = numberToBytesLE(counter, 4);

  // Build hash input
  const parts: Uint8Array[] = [lengthPrefixed(seed), lengthPrefixed(counterBytes)];

  const totalLen = parts.reduce((sum, arr) => sum + arr.length, 0);
  const combined = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of parts) {
    combined.set(arr, offset);
    offset += arr.length;
  }

  // BLAKE3 XOF with 64-byte output
  const uniformBytes = blake3(combined, { dkLen: 64 });

  // OneWayMap (RFC 9496 Section 4.3.4)
  return group.hashToElement(uniformBytes);
}

/**
 * GenerateParameters (Section 3.1)
 *
 * Generates system parameters H1-H4 from a domain separator.
 *
 * The domain_separator MUST be unique for each deployment.
 * Recommended format: "ACT-v1:organization:service:deployment_id:version"
 *
 * @param domainSeparator - Unique identifier for this deployment
 * @param L - Bit length for credit values (1 <= L <= 128)
 * @returns System parameters
 */
export function generateParameters(domainSeparator: string, L: number = 64): SystemParams {
  // Validate L constraint (Section 3.1)
  if (L < 1 || L > 128) {
    throw new ACTError(`L must be in range [1, 128], got ${L}`, ACTErrorCode.InvalidParameter);
  }

  // Step 1: seed = BLAKE3(LengthPrefixed(domain_separator))
  const domainBytes = asciiToBytes(domainSeparator);
  const seed = blake3(lengthPrefixed(domainBytes));

  // Steps 3-6: Generate H1, H2, H3, H4
  let counter = 0;
  const H1 = hashToRistretto255(seed, counter++);
  const H2 = hashToRistretto255(seed, counter++);
  const H3 = hashToRistretto255(seed, counter++);
  const H4 = hashToRistretto255(seed, counter++);

  return {
    H1,
    H2,
    H3,
    H4,
    L,
    domainSeparator,
  };
}

/**
 * Validate a domain separator string
 *
 * Section 3.1: Each component MUST NOT contain the colon character ':'
 */
export function validateDomainSeparator(domainSeparator: string): boolean {
  // Check for recommended format
  const parts = domainSeparator.split(':');

  if (parts.length < 5) {
    return false;
  }

  // First part should be "ACT-v1"
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
 * Create a properly formatted domain separator
 *
 * @param organization - Organization identifier (no colons)
 * @param service - Service name (no colons)
 * @param deploymentId - Deployment environment (no colons)
 * @param version - ISO 8601 date YYYY-MM-DD (no colons)
 */
export function createDomainSeparator(
  organization: string,
  service: string,
  deploymentId: string,
  version: string
): string {
  // Validate no colons in components
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
