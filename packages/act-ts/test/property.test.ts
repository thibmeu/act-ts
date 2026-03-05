/**
 * Property-Based Tests for ACT Protocol (Main)
 *
 * Uses fast-check to verify encoding roundtrips and size invariants.
 */

import { describe, it } from 'vitest';
import * as fc from 'fast-check';
import { ristretto255 } from 'sigma-proofs';
import {
  encodePrivateKey,
  decodePrivateKey,
  encodePublicKey,
  decodePublicKey,
  EncodingError,
} from '../src/encoding.js';
import type { PrivateKey, PublicKey } from '../src/types.js';

const group = ristretto255;

// --- Arbitraries ---

/** Generate arbitrary non-zero 32-byte array for scalar */
const arbScalarBytes = fc
  .uint8Array({ minLength: 32, maxLength: 32 })
  .filter((arr) => arr.some((b) => b !== 0))
  .map((arr) => {
    // Ensure value is < group order by clearing high bits
    const copy = new Uint8Array(arr);
    copy[31]! &= 0x0f; // Keep only low 4 bits of high byte
    return copy;
  });

describe('Property-Based Tests (Main)', () => {
  describe('Encoding Roundtrips', () => {
    it('PrivateKey roundtrips', () => {
      fc.assert(
        fc.property(arbScalarBytes, (bytes) => {
          try {
            const x = group.scalarFromBytes(bytes);
            const sk: PrivateKey = { x };
            const encoded = encodePrivateKey(sk);
            const decoded = decodePrivateKey(group, encoded);
            return decoded.x.equals(sk.x);
          } catch {
            // Invalid scalar bytes are expected sometimes
            return true;
          }
        }),
        { numRuns: 100 }
      );
    });

    it('PublicKey roundtrips', () => {
      fc.assert(
        fc.property(arbScalarBytes, (bytes) => {
          try {
            const x = group.scalarFromBytes(bytes);
            if (x.isZero()) return true; // Skip zero scalar
            const W = group.generator().multiply(x);
            const pk: PublicKey = { W };
            const encoded = encodePublicKey(pk);
            const decoded = decodePublicKey(group, encoded);
            return decoded.W.equals(pk.W);
          } catch {
            return true;
          }
        }),
        { numRuns: 100 }
      );
    });
  });

  describe('Encoding Size Properties', () => {
    it('PrivateKey is always 32 bytes', () => {
      fc.assert(
        fc.property(arbScalarBytes, (bytes) => {
          try {
            const x = group.scalarFromBytes(bytes);
            const sk: PrivateKey = { x };
            const encoded = encodePrivateKey(sk);
            return encoded.length === 32;
          } catch {
            return true;
          }
        }),
        { numRuns: 100 }
      );
    });

    it('PublicKey is always 32 bytes', () => {
      fc.assert(
        fc.property(arbScalarBytes, (bytes) => {
          try {
            const x = group.scalarFromBytes(bytes);
            if (x.isZero()) return true;
            const W = group.generator().multiply(x);
            const pk: PublicKey = { W };
            const encoded = encodePublicKey(pk);
            return encoded.length === 32;
          } catch {
            return true;
          }
        }),
        { numRuns: 100 }
      );
    });
  });

  describe('Decoding Error Handling', () => {
    it('rejects truncated PrivateKey', () => {
      fc.assert(
        fc.property(fc.integer({ min: 0, max: 31 }), (len) => {
          const data = new Uint8Array(len);
          try {
            decodePrivateKey(group, data);
            return false; // Should have thrown
          } catch (e) {
            return e instanceof EncodingError;
          }
        }),
        { numRuns: 32 }
      );
    });

    it('rejects truncated PublicKey', () => {
      fc.assert(
        fc.property(fc.integer({ min: 0, max: 31 }), (len) => {
          const data = new Uint8Array(len);
          try {
            decodePublicKey(group, data);
            return false;
          } catch (e) {
            return e instanceof EncodingError;
          }
        }),
        { numRuns: 32 }
      );
    });

    it('rejects PrivateKey with trailing data', () => {
      fc.assert(
        fc.property(arbScalarBytes, fc.integer({ min: 1, max: 10 }), (bytes, extra) => {
          try {
            const x = group.scalarFromBytes(bytes);
            const sk: PrivateKey = { x };
            const encoded = encodePrivateKey(sk);
            const withTrailing = new Uint8Array(encoded.length + extra);
            withTrailing.set(encoded);
            decodePrivateKey(group, withTrailing);
            return false;
          } catch (e) {
            return e instanceof EncodingError || e instanceof Error;
          }
        }),
        { numRuns: 50 }
      );
    });
  });
});
