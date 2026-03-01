/**
 * Tests for ACT VNEXT (sigma-draft-compliance)
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  ristretto255,
  generateParameters,
  keyGen,
  issueRequest,
  issueResponse,
  verifyIssuance,
  proveSpend,
  verifySpendProof,
  issueRefund,
  constructRefundToken,
  verifyAndRefund,
  SeededPRNG,
  ACTError,
  type SystemParams,
  type KeyPair,
  type PRNG,
} from '../src/index-vnext.js';

describe('ACT VNEXT', () => {
  const group = ristretto255;
  let params: SystemParams;
  let issuerKeys: KeyPair;

  // Create a fresh RNG for each test to avoid state pollution
  function makeRng(testSeed: number): PRNG {
    const seed = new Uint8Array(32);
    seed[0] = testSeed;
    return new SeededPRNG(seed);
  }

  beforeAll(() => {
    const rng = makeRng(0x42);

    // Generate system parameters (L >= 4 required for range proof to work)
    params = generateParameters(group, 'ACT-v1:test:unit:local:2026-03-01', 8);

    // Generate issuer keys
    issuerKeys = keyGen(group, rng);
  });

  describe('Parameters', () => {
    it('generates distinct generators', () => {
      const { H1, H2, H3, H4 } = params;
      const G = group.generator();

      // All should be distinct
      expect(H1.equals(H2)).toBe(false);
      expect(H1.equals(H3)).toBe(false);
      expect(H1.equals(H4)).toBe(false);
      expect(H2.equals(H3)).toBe(false);
      expect(H2.equals(H4)).toBe(false);
      expect(H3.equals(H4)).toBe(false);

      // None should be identity or base generator
      expect(H1.equals(group.identity())).toBe(false);
      expect(H2.equals(group.identity())).toBe(false);
      expect(H3.equals(group.identity())).toBe(false);
      expect(H4.equals(group.identity())).toBe(false);
      expect(H1.equals(G)).toBe(false);
      expect(H2.equals(G)).toBe(false);
      expect(H3.equals(G)).toBe(false);
      expect(H4.equals(G)).toBe(false);
    });

    it('validates L range', () => {
      expect(() => generateParameters(group, 'test', 0)).toThrow();
      expect(() => generateParameters(group, 'test', 129)).toThrow();
      expect(() => generateParameters(group, 'test', 1)).not.toThrow();
      expect(() => generateParameters(group, 'test', 128)).not.toThrow();
    });
  });

  describe('Issuance', () => {
    it('completes full issuance flow', () => {
      const rng = makeRng(0x10);
      const ctx = group.scalarFromBigint(0x1234n);
      const creditAmount = 100n;

      // Client creates request
      const [request, state] = issueRequest(params, ctx, rng);
      expect(request.K).toBeDefined();
      expect(request.pok.length).toBeGreaterThan(0);

      // Issuer creates response
      const response = issueResponse(
        params,
        issuerKeys.privateKey,
        request,
        creditAmount,
        ctx,
        rng
      );
      expect(response.A).toBeDefined();
      expect(response.c).toBe(creditAmount);

      // Client verifies and gets token
      const token = verifyIssuance(params, issuerKeys.publicKey, response, state);
      expect(token.c).toBe(creditAmount);
      expect(token.k.equals(state.k)).toBe(true);
      expect(token.r.equals(state.r)).toBe(true);
    });

    it('rejects invalid credit amount', () => {
      const rng = makeRng(0x11);
      const ctx = group.scalarFromBigint(0n);
      const [request, _] = issueRequest(params, ctx, rng);

      // Negative amount
      expect(() =>
        issueResponse(params, issuerKeys.privateKey, request, -1n, ctx, rng)
      ).toThrow(ACTError);

      // Amount too large (>= 2^L where L=8)
      expect(() =>
        issueResponse(params, issuerKeys.privateKey, request, 256n, ctx, rng)
      ).toThrow(ACTError);
    });

    it('rejects tampered proof', () => {
      const rng = makeRng(0x12);
      const ctx = group.scalarFromBigint(0n);
      const [request, _] = issueRequest(params, ctx, rng);

      // Tamper with the proof
      const tamperedPok = new Uint8Array(request.pok);
      tamperedPok[0] ^= 0xff;
      const tamperedRequest = { ...request, pok: tamperedPok };

      expect(() =>
        issueResponse(params, issuerKeys.privateKey, tamperedRequest, 50n, ctx, rng)
      ).toThrow(ACTError);
    });
  });

  describe('Spending', () => {
    it('completes full spend flow', () => {
      const rng = makeRng(0x20);
      const ctx = group.scalarFromBigint(0x5678n);
      const creditAmount = 100n;
      const spendAmount = 30n;

      // Issue token
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(
        params,
        issuerKeys.privateKey,
        request,
        creditAmount,
        ctx,
        rng
      );
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);

      // Spend
      const [spendProof, spendState] = proveSpend(params, token, spendAmount, rng);
      expect(spendProof.s).toBe(spendAmount);
      expect(spendProof.Com.length).toBe(params.L);

      // Verify
      expect(() => verifySpendProof(params, issuerKeys.privateKey, spendProof)).not.toThrow();

      // Issue refund (no partial return)
      const usedNullifiers = new Set<string>();
      const refund = verifyAndRefund(
        params,
        issuerKeys.privateKey,
        spendProof,
        usedNullifiers,
        0n,
        rng
      );

      // Construct new token
      const newToken = constructRefundToken(
        params,
        issuerKeys.publicKey,
        spendProof,
        refund,
        spendState
      );

      // New token should have balance = c - s + t = 100 - 30 + 0 = 70
      expect(newToken.c).toBe(70n);
    });

    it('handles partial refund', () => {
      const rng = makeRng(0x21);
      const ctx = group.scalarFromBigint(0n);
      const creditAmount = 100n;
      const spendAmount = 50n;
      const refundAmount = 20n;

      // Issue token
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(
        params,
        issuerKeys.privateKey,
        request,
        creditAmount,
        ctx,
        rng
      );
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);

      // Spend
      const [spendProof, spendState] = proveSpend(params, token, spendAmount, rng);

      // Verify and refund with partial return
      const usedNullifiers = new Set<string>();
      const refund = verifyAndRefund(
        params,
        issuerKeys.privateKey,
        spendProof,
        usedNullifiers,
        refundAmount,
        rng
      );
      expect(refund.t).toBe(refundAmount);

      // Construct new token
      const newToken = constructRefundToken(
        params,
        issuerKeys.publicKey,
        spendProof,
        refund,
        spendState
      );

      // New token should have balance = c - s + t = 100 - 50 + 20 = 70
      expect(newToken.c).toBe(70n);
    });

    it('detects double spend', () => {
      const rng = makeRng(0x22);
      const ctx = group.scalarFromBigint(0n);

      // Issue token
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(
        params,
        issuerKeys.privateKey,
        request,
        100n,
        ctx,
        rng
      );
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);

      // First spend
      const [spendProof, _] = proveSpend(params, token, 50n, rng);
      const usedNullifiers = new Set<string>();
      verifyAndRefund(params, issuerKeys.privateKey, spendProof, usedNullifiers, 0n, rng);

      // Second spend with same nullifier should fail
      expect(() =>
        verifyAndRefund(params, issuerKeys.privateKey, spendProof, usedNullifiers, 0n, rng)
      ).toThrow(ACTError);
    });

    it('rejects spend exceeding balance', () => {
      const rng = makeRng(0x23);
      const ctx = group.scalarFromBigint(0n);

      // Issue token with 50 credits
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(
        params,
        issuerKeys.privateKey,
        request,
        50n,
        ctx,
        rng
      );
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);

      // Try to spend 100
      expect(() => proveSpend(params, token, 100n, rng)).toThrow(ACTError);
    });

    it('rejects refund exceeding spend amount', () => {
      const rng = makeRng(0x24);
      const ctx = group.scalarFromBigint(0n);

      // Issue and spend
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(
        params,
        issuerKeys.privateKey,
        request,
        100n,
        ctx,
        rng
      );
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);
      const [spendProof, _] = proveSpend(params, token, 30n, rng);

      // Verify succeeds
      verifySpendProof(params, issuerKeys.privateKey, spendProof);

      // Try to refund more than spent
      expect(() =>
        issueRefund(params, issuerKeys.privateKey, spendProof, 50n, rng)
      ).toThrow(ACTError);
    });
  });

  describe('Edge cases', () => {
    it('handles zero credit issuance', () => {
      const rng = makeRng(0x30);
      const ctx = group.scalarFromBigint(0n);

      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(
        params,
        issuerKeys.privateKey,
        request,
        0n,
        ctx,
        rng
      );
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);

      expect(token.c).toBe(0n);
    });

    it('handles zero spend', () => {
      const rng = makeRng(0x31);
      const ctx = group.scalarFromBigint(0n);

      // Issue token
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(
        params,
        issuerKeys.privateKey,
        request,
        100n,
        ctx,
        rng
      );
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);

      // Spend 0
      const [spendProof, spendState] = proveSpend(params, token, 0n, rng);
      verifySpendProof(params, issuerKeys.privateKey, spendProof);

      // Refund with full spend back
      const refund = issueRefund(params, issuerKeys.privateKey, spendProof, 0n, rng);
      const newToken = constructRefundToken(
        params,
        issuerKeys.publicKey,
        spendProof,
        refund,
        spendState
      );

      // Balance should be unchanged
      expect(newToken.c).toBe(100n);
    });

    it('handles full spend', () => {
      const rng = makeRng(0x32);
      const ctx = group.scalarFromBigint(0n);

      // Issue token
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(
        params,
        issuerKeys.privateKey,
        request,
        100n,
        ctx,
        rng
      );
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);

      // Spend entire balance
      const [spendProof, spendState] = proveSpend(params, token, 100n, rng);
      verifySpendProof(params, issuerKeys.privateKey, spendProof);

      // Refund 0
      const refund = issueRefund(params, issuerKeys.privateKey, spendProof, 0n, rng);
      const newToken = constructRefundToken(
        params,
        issuerKeys.publicKey,
        spendProof,
        refund,
        spendState
      );

      // Balance should be 0
      expect(newToken.c).toBe(0n);
    });

    it('handles max L value', () => {
      const rng = makeRng(0x33);
      const ctx = group.scalarFromBigint(0n);
      const maxValue = (1n << BigInt(params.L)) - 1n; // 255 for L=8

      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(
        params,
        issuerKeys.privateKey,
        request,
        maxValue,
        ctx,
        rng
      );
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);

      expect(token.c).toBe(maxValue);

      // Spend all
      const [spendProof, _] = proveSpend(params, token, maxValue, rng);
      verifySpendProof(params, issuerKeys.privateKey, spendProof);
    });
  });
});
