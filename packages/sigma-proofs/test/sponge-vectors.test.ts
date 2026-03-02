/**
 * Test vectors for SHAKE128 duplex sponge.
 *
 * Vectors from: https://github.com/mmaker/draft-irtf-cfrg-sigma-protocols/tree/main/poc/vectors
 */
import { describe, it, expect } from 'vitest';
import { Shake128Sponge } from '../src/index.js';
import { bytesToHex } from '@noble/curves/utils.js';
import duplexVectors from './vectors/duplexSpongeVectors.json';

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

interface Operation {
  type: 'absorb' | 'squeeze';
  data?: string;
  length?: number;
}

interface SpongeVector {
  DuplexSponge: string;
  IV: string;
  Operations: Operation[];
  Expected: string;
}

describe('SHAKE128 duplex sponge spec vectors', () => {
  for (const [name, vec] of Object.entries(duplexVectors) as [string, SpongeVector][]) {
    if (vec.DuplexSponge !== 'SHAKE128') {
      continue;
    }

    it(name, () => {
      const iv = hexToBytes(vec.IV);
      const sponge = new Shake128Sponge(iv);

      let lastSqueeze: Uint8Array = new Uint8Array(0);

      for (const op of vec.Operations) {
        if (op.type === 'absorb') {
          const data = op.data ? hexToBytes(op.data) : new Uint8Array(0);
          sponge.absorb(data);
        } else if (op.type === 'squeeze') {
          const length = op.length ?? 0;
          if (length > 0) {
            lastSqueeze = sponge.squeeze(length);
          }
        }
      }

      expect(bytesToHex(lastSqueeze)).toBe(vec.Expected);
    });
  }
});
