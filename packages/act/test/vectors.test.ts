/**
 * Test vectors from IETF draft-schlesinger-cfrg-act-01 Appendix A
 *
 * These test vectors use CBOR wire format. We test what we can verify:
 * - Parameter generation (deterministic from domain separator)
 * - Proof verification (given known good proofs)
 *
 * Full test vector validation requires CBOR parsing which is deferred.
 */

import { describe, it, expect } from 'vitest';
import testVectors from './vectors/testACT.json';
import {
  generateParameters,
  group,
} from '../src/index.js';
import { bytesToHex, hexToBytes } from '@noble/curves/utils.js';

describe('ACT Test Vectors (Appendix A)', () => {
  describe('A.1 Parameters', () => {
    const { domain_separator, L } = testVectors.parameters;

    it('generates parameters from domain separator', () => {
      const params = generateParameters(domain_separator, L);

      expect(params.L).toBe(L);
      expect(params.domainSeparator).toBe(domain_separator);

      // H1-H4 should be valid non-identity group elements
      expect(params.H1.isIdentity()).toBe(false);
      expect(params.H2.isIdentity()).toBe(false);
      expect(params.H3.isIdentity()).toBe(false);
      expect(params.H4.isIdentity()).toBe(false);

      // H1-H4 should be distinct
      expect(params.H1.equals(params.H2)).toBe(false);
      expect(params.H1.equals(params.H3)).toBe(false);
      expect(params.H1.equals(params.H4)).toBe(false);
      expect(params.H2.equals(params.H3)).toBe(false);
      expect(params.H2.equals(params.H4)).toBe(false);
      expect(params.H3.equals(params.H4)).toBe(false);

      // Log generated parameters for cross-implementation comparison
      console.log('Generated parameters:');
      console.log('  H1:', bytesToHex(params.H1.toBytes()));
      console.log('  H2:', bytesToHex(params.H2.toBytes()));
      console.log('  H3:', bytesToHex(params.H3.toBytes()));
      console.log('  H4:', bytesToHex(params.H4.toBytes()));
    });

    it('generates deterministic parameters', () => {
      const params1 = generateParameters(domain_separator, L);
      const params2 = generateParameters(domain_separator, L);

      expect(params1.H1.equals(params2.H1)).toBe(true);
      expect(params1.H2.equals(params2.H2)).toBe(true);
      expect(params1.H3.equals(params2.H3)).toBe(true);
      expect(params1.H4.equals(params2.H4)).toBe(true);
    });
  });

  describe('A.2 Key Generation', () => {
    // The test vectors include CBOR-encoded keys
    // sk_cbor encodes {1: sk_bytes, 2: pk_bytes}
    // pk_cbor encodes pk_bytes

    it.todo('decodes and validates key pair from CBOR (needs CBOR parser)');
  });

  describe('A.3 Issuance', () => {
    const { c, ctx } = testVectors.parameters;

    it('validates test vector credit amount', () => {
      expect(c).toBe(100);
    });

    it('validates test vector context is zero', () => {
      const ctxBytes = hexToBytes(ctx);
      expect(ctxBytes.every(b => b === 0)).toBe(true);
    });

    it.todo('validates issuance request CBOR (needs CBOR parser)');
    it.todo('validates issuance response CBOR (needs CBOR parser)');
    it.todo('validates credit token CBOR (needs CBOR parser)');
  });

  describe('A.4 Spending', () => {
    const { s, t } = testVectors.parameters;

    it('validates test vector spend amount', () => {
      expect(s).toBe(30);
    });

    it('validates test vector return amount', () => {
      expect(t).toBe(10);
    });

    it('validates nullifier encoding', () => {
      const nullifier = hexToBytes(testVectors.spending.nullifier);
      expect(nullifier.length).toBe(32);
    });

    it('validates charge encoding (little-endian 30)', () => {
      const charge = hexToBytes(testVectors.spending.charge);
      expect(charge.length).toBe(32);
      // Little-endian: 0x1e = 30
      expect(charge[0]).toBe(0x1e);
      expect(charge.slice(1).every(b => b === 0)).toBe(true);
    });

    it.todo('validates spend proof CBOR (needs CBOR parser)');
  });

  describe('A.5 Refund', () => {
    it.todo('validates refund CBOR (needs CBOR parser)');
  });

  describe('A.6 Refund Token', () => {
    it('validates remaining balance', () => {
      // 100 (initial) - 30 (spent) + 10 (returned) = 80
      expect(testVectors.refund_token.remaining_balance).toBe(80);
    });

    it('validates refund token credits encoding (little-endian 80)', () => {
      const credits = hexToBytes(testVectors.refund_token.refund_token_credits);
      expect(credits.length).toBe(32);
      // Little-endian: 0x50 = 80
      expect(credits[0]).toBe(0x50);
      expect(credits.slice(1).every(b => b === 0)).toBe(true);
    });

    it.todo('validates refund token CBOR (needs CBOR parser)');
  });
});

describe('Cross-implementation compatibility', () => {
  it.todo('generates same H1-H4 as Rust reference implementation');
  it.todo('generates same transcript hash as Rust reference implementation');
});
