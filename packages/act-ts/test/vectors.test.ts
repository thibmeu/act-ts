/**
 * Test vectors from IETF draft-schlesinger-cfrg-act-01 Appendix A
 *
 * These test vectors validate CBOR wire format encoding/decoding
 * and cross-implementation compatibility.
 */

import { describe, it, expect } from 'vitest';
import testVectors from './vectors/testACT.json';
import {
  generateParameters,
  group,
  decodeKeyPair,
  decodePublicKey,
  decodeIssuanceRequest,
  decodeIssuanceResponse,
  decodeCreditToken,
  decodeSpendProof,
  decodeRefund,
  decodePreIssuance,
  decodePreRefund,
  encodeIssuanceRequest,
  encodeIssuanceResponse,
  encodeCreditToken,
  encodeSpendProof,
  encodeRefund,
  encodePreIssuance,
  encodePreRefund,
  encodeKeyPair,
  encodePublicKey,
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
    it('decodes key pair from CBOR', () => {
      const data = hexToBytes(testVectors.key_generation.sk_cbor);
      const { privateKey, publicKey } = decodeKeyPair(data);

      expect(privateKey.x).toBeDefined();
      expect(publicKey.W).toBeDefined();
      expect(publicKey.W.isIdentity()).toBe(false);

      // Verify pk = G * sk
      const derived = group.generator().multiply(privateKey.x);
      expect(derived.equals(publicKey.W)).toBe(true);

      console.log('Key pair:');
      console.log('  sk:', bytesToHex(privateKey.x.toBytes()));
      console.log('  pk:', bytesToHex(publicKey.W.toBytes()));
    });

    it('decodes public key from CBOR', () => {
      const data = hexToBytes(testVectors.key_generation.pk_cbor);
      const publicKey = decodePublicKey(data);

      expect(publicKey.W.isIdentity()).toBe(false);
    });

    it('round-trips key pair encoding', () => {
      const data = hexToBytes(testVectors.key_generation.sk_cbor);
      const { privateKey, publicKey } = decodeKeyPair(data);

      const reencoded = encodeKeyPair(privateKey, publicKey);
      const { privateKey: sk2, publicKey: pk2 } = decodeKeyPair(reencoded);

      expect(sk2.x.equals(privateKey.x)).toBe(true);
      expect(pk2.W.equals(publicKey.W)).toBe(true);
    });
  });

  describe('A.3 Issuance', () => {
    const { c, ctx } = testVectors.parameters;

    it('validates test vector credit amount', () => {
      expect(c).toBe(100);
    });

    it('validates test vector context is zero', () => {
      const ctxBytes = hexToBytes(ctx);
      expect(ctxBytes.every((b) => b === 0)).toBe(true);
    });

    it('decodes pre-issuance state from CBOR', () => {
      const data = hexToBytes(testVectors.issuance.preissuance_cbor);
      const state = decodePreIssuance(data);

      expect(state.k).toBeDefined();
      expect(state.r).toBeDefined();

      console.log('Pre-issuance:');
      console.log('  k:', bytesToHex(state.k.toBytes()));
      console.log('  r:', bytesToHex(state.r.toBytes()));
    });

    it('decodes issuance request from CBOR', () => {
      const data = hexToBytes(testVectors.issuance.issuance_request_cbor);
      const request = decodeIssuanceRequest(data);

      expect(request.K).toBeDefined();
      expect(request.gamma).toBeDefined();
      expect(request.kBar).toBeDefined();
      expect(request.rBar).toBeDefined();

      console.log('Issuance request:');
      console.log('  K:', bytesToHex(request.K.toBytes()));
      console.log('  gamma:', bytesToHex(request.gamma.toBytes()));
    });

    it('decodes issuance response from CBOR', () => {
      const data = hexToBytes(testVectors.issuance.issuance_response_cbor);
      const response = decodeIssuanceResponse(data);

      expect(response.A).toBeDefined();
      expect(response.e).toBeDefined();
      expect(response.gammaResp).toBeDefined();
      expect(response.z).toBeDefined();
      expect(response.c).toBe(100n);
      expect(response.ctx).toBeDefined();

      console.log('Issuance response:');
      console.log('  A:', bytesToHex(response.A.toBytes()));
      console.log('  c:', response.c);
    });

    it('decodes credit token from CBOR', () => {
      const data = hexToBytes(testVectors.issuance.credit_token_cbor);
      const token = decodeCreditToken(data);

      expect(token.A).toBeDefined();
      expect(token.e).toBeDefined();
      expect(token.k).toBeDefined();
      expect(token.r).toBeDefined();
      expect(token.c).toBe(100n);
      expect(token.ctx).toBeDefined();

      console.log('Credit token:');
      console.log('  A:', bytesToHex(token.A.toBytes()));
      console.log('  k (nullifier):', bytesToHex(token.k.toBytes()));
      console.log('  c:', token.c);
    });

    it('round-trips issuance request encoding', () => {
      const data = hexToBytes(testVectors.issuance.issuance_request_cbor);
      const request = decodeIssuanceRequest(data);
      const reencoded = encodeIssuanceRequest(request);
      const decoded2 = decodeIssuanceRequest(reencoded);

      expect(decoded2.K.equals(request.K)).toBe(true);
      expect(decoded2.gamma.equals(request.gamma)).toBe(true);
      expect(decoded2.kBar.equals(request.kBar)).toBe(true);
      expect(decoded2.rBar.equals(request.rBar)).toBe(true);
    });

    it('round-trips issuance response encoding', () => {
      const data = hexToBytes(testVectors.issuance.issuance_response_cbor);
      const response = decodeIssuanceResponse(data);
      const reencoded = encodeIssuanceResponse(response);
      const decoded2 = decodeIssuanceResponse(reencoded);

      expect(decoded2.A.equals(response.A)).toBe(true);
      expect(decoded2.e.equals(response.e)).toBe(true);
      expect(decoded2.c).toBe(response.c);
    });

    it('round-trips credit token encoding', () => {
      const data = hexToBytes(testVectors.issuance.credit_token_cbor);
      const token = decodeCreditToken(data);
      const reencoded = encodeCreditToken(token);
      const decoded2 = decodeCreditToken(reencoded);

      expect(decoded2.A.equals(token.A)).toBe(true);
      expect(decoded2.k.equals(token.k)).toBe(true);
      expect(decoded2.c).toBe(token.c);
    });
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
      expect(charge.slice(1).every((b) => b === 0)).toBe(true);
    });

    it.todo('decodes spend proof from CBOR (vector truncated in JSON)');

    it('decodes pre-refund state from CBOR', () => {
      const data = hexToBytes(testVectors.spending.prerefund_cbor);
      const state = decodePreRefund(data);

      expect(state.kStar).toBeDefined();
      expect(state.rStar).toBeDefined();
      expect(state.m).toBe(70n); // 100 - 30 = 70
      expect(state.ctx).toBeDefined();

      console.log('Pre-refund state:');
      console.log('  k* (new nullifier):', bytesToHex(state.kStar.toBytes()));
      console.log('  m (remaining):', state.m);
    });

    it.todo('round-trips spend proof encoding (vector truncated in JSON)');
  });

  describe('A.5 Refund', () => {
    it('decodes refund from CBOR', () => {
      const data = hexToBytes(testVectors.refund.refund_cbor);
      const refund = decodeRefund(data);

      expect(refund.AStar).toBeDefined();
      expect(refund.eStar).toBeDefined();
      expect(refund.gamma).toBeDefined();
      expect(refund.z).toBeDefined();
      expect(refund.t).toBe(10n);

      console.log('Refund:');
      console.log('  A*:', bytesToHex(refund.AStar.toBytes()));
      console.log('  t (return):', refund.t);
    });

    it('round-trips refund encoding', () => {
      const data = hexToBytes(testVectors.refund.refund_cbor);
      const refund = decodeRefund(data);
      const reencoded = encodeRefund(refund);
      const decoded2 = decodeRefund(reencoded);

      expect(decoded2.AStar.equals(refund.AStar)).toBe(true);
      expect(decoded2.eStar.equals(refund.eStar)).toBe(true);
      expect(decoded2.t).toBe(refund.t);
    });
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
      expect(credits.slice(1).every((b) => b === 0)).toBe(true);
    });

    it('decodes refund token from CBOR', () => {
      const data = hexToBytes(testVectors.refund_token.refund_token_cbor);
      const token = decodeCreditToken(data);

      expect(token.A).toBeDefined();
      expect(token.e).toBeDefined();
      expect(token.k).toBeDefined();
      expect(token.r).toBeDefined();
      expect(token.c).toBe(80n); // 100 - 30 + 10 = 80
      expect(token.ctx).toBeDefined();

      // Verify nullifier matches expected
      const expectedNullifier = testVectors.refund_token.refund_token_nullifier;
      expect(bytesToHex(token.k.toBytes())).toBe(expectedNullifier);

      console.log('Refund token:');
      console.log('  A:', bytesToHex(token.A.toBytes()));
      console.log('  k (nullifier):', bytesToHex(token.k.toBytes()));
      console.log('  c:', token.c);
    });
  });

  describe('Cross-implementation consistency', () => {
    it.todo('nullifier in spend proof matches token nullifier (vector truncated)');

    it('refund token has different nullifier than original', () => {
      // Decode original credit token
      const tokenData = hexToBytes(testVectors.issuance.credit_token_cbor);
      const originalToken = decodeCreditToken(tokenData);

      // Decode refund token
      const refundTokenData = hexToBytes(testVectors.refund_token.refund_token_cbor);
      const refundToken = decodeCreditToken(refundTokenData);

      // Nullifiers should be different (unlinkability)
      expect(refundToken.k.equals(originalToken.k)).toBe(false);
    });

    it('balance arithmetic is correct (without spend proof)', () => {
      const { c, s, t } = testVectors.parameters;

      // Original balance
      const tokenData = hexToBytes(testVectors.issuance.credit_token_cbor);
      const token = decodeCreditToken(tokenData);
      expect(token.c).toBe(BigInt(c));

      // Return amount
      const refundData = hexToBytes(testVectors.refund.refund_cbor);
      const refund = decodeRefund(refundData);
      expect(refund.t).toBe(BigInt(t));

      // Final balance
      const refundTokenData = hexToBytes(testVectors.refund_token.refund_token_cbor);
      const refundToken = decodeCreditToken(refundTokenData);
      expect(refundToken.c).toBe(BigInt(c - s + t)); // 100 - 30 + 10 = 80
    });
  });
});
