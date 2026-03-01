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
      expect(() => issueResponse(params, issuerKeys.privateKey, request, -1n, ctx, rng)).toThrow(
        ACTError
      );

      // Amount too large (>= 2^L where L=8)
      expect(() => issueResponse(params, issuerKeys.privateKey, request, 256n, ctx, rng)).toThrow(
        ACTError
      );
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
      const response = issueResponse(params, issuerKeys.privateKey, request, 100n, ctx, rng);
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
      const response = issueResponse(params, issuerKeys.privateKey, request, 50n, ctx, rng);
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);

      // Try to spend 100
      expect(() => proveSpend(params, token, 100n, rng)).toThrow(ACTError);
    });

    it('rejects refund exceeding spend amount', () => {
      const rng = makeRng(0x24);
      const ctx = group.scalarFromBigint(0n);

      // Issue and spend
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(params, issuerKeys.privateKey, request, 100n, ctx, rng);
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);
      const [spendProof, _] = proveSpend(params, token, 30n, rng);

      // Verify succeeds
      verifySpendProof(params, issuerKeys.privateKey, spendProof);

      // Try to refund more than spent
      expect(() => issueRefund(params, issuerKeys.privateKey, spendProof, 50n, rng)).toThrow(
        ACTError
      );
    });
  });

  describe('Edge cases', () => {
    it('handles zero credit issuance', () => {
      const rng = makeRng(0x30);
      const ctx = group.scalarFromBigint(0n);

      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(params, issuerKeys.privateKey, request, 0n, ctx, rng);
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);

      expect(token.c).toBe(0n);
    });

    it('handles zero spend', () => {
      const rng = makeRng(0x31);
      const ctx = group.scalarFromBigint(0n);

      // Issue token
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(params, issuerKeys.privateKey, request, 100n, ctx, rng);
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
      const response = issueResponse(params, issuerKeys.privateKey, request, 100n, ctx, rng);
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
      const response = issueResponse(params, issuerKeys.privateKey, request, maxValue, ctx, rng);
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);

      expect(token.c).toBe(maxValue);

      // Spend all
      const [spendProof, _] = proveSpend(params, token, maxValue, rng);
      verifySpendProof(params, issuerKeys.privateKey, spendProof);
    });
  });

  describe('Security tests', () => {
    it('handles large amount issuance (2^126)', { timeout: 30000 }, () => {
      // Use L=128 to accommodate large values
      const paramsL128 = generateParameters(group, 'ACT-v1:test:security:large:2026', 128);
      const rng = makeRng(0x40);
      const keysL128 = keyGen(group, rng);
      const ctx = group.scalarFromBigint(0n);

      // Issue 2^126 credits
      const largeAmount = 1n << 126n;
      const [request, issueState] = issueRequest(paramsL128, ctx, rng);
      const response = issueResponse(
        paramsL128,
        keysL128.privateKey,
        request,
        largeAmount,
        ctx,
        rng
      );
      const token = verifyIssuance(paramsL128, keysL128.publicKey, response, issueState);
      expect(token.c).toBe(largeAmount);

      // Spend half
      const spendAmount = largeAmount / 2n;
      const [spendProof, spendState] = proveSpend(paramsL128, token, spendAmount, rng);
      verifySpendProof(paramsL128, keysL128.privateKey, spendProof);

      // Refund
      const refund = issueRefund(paramsL128, keysL128.privateKey, spendProof, 0n, rng);
      const newToken = constructRefundToken(
        paramsL128,
        keysL128.publicKey,
        spendProof,
        refund,
        spendState
      );
      expect(newToken.c).toBe(largeAmount - spendAmount);
    });

    it('exhaustively spends 1 credit at a time', { timeout: 30000 }, () => {
      const rng = makeRng(0x41);
      const ctx = group.scalarFromBigint(0n);
      const initialCredits = 10n;

      // Issue token with 10 credits
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(
        params,
        issuerKeys.privateKey,
        request,
        initialCredits,
        ctx,
        rng
      );
      let token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);
      const nullifiers: string[] = [];

      // Spend 1 credit at a time
      for (let i = 0n; i < initialCredits; i++) {
        const [spendProof, spendState] = proveSpend(params, token, 1n, rng);
        verifySpendProof(params, issuerKeys.privateKey, spendProof);

        // Track nullifier (as hex string for easy comparison)
        const nullifierHex = Buffer.from(spendProof.k.toBytes()).toString('hex');
        expect(nullifiers).not.toContain(nullifierHex);
        nullifiers.push(nullifierHex);

        // Get refund token for next iteration
        const refund = issueRefund(params, issuerKeys.privateKey, spendProof, 0n, rng);
        token = constructRefundToken(params, issuerKeys.publicKey, spendProof, refund, spendState);
        expect(token.c).toBe(initialCredits - i - 1n);
      }

      // Token should be exhausted
      expect(token.c).toBe(0n);
    });

    it('nullifier collision check (15 tokens)', { timeout: 30000 }, () => {
      // Use L=4 for speed, smaller token count
      const paramsL4 = generateParameters(group, 'ACT-v1:test:collision:local:2026', 4);
      const rng = makeRng(0x42);
      const keysL4 = keyGen(group, rng);
      const ctx = group.scalarFromBigint(0n);
      const nullifiers = new Set<string>();

      // Create 15 tokens and collect nullifiers (faster with L=4)
      for (let i = 0; i < 15; i++) {
        const [request, issueState] = issueRequest(paramsL4, ctx, rng);
        const response = issueResponse(paramsL4, keysL4.privateKey, request, 10n, ctx, rng);
        const token = verifyIssuance(paramsL4, keysL4.publicKey, response, issueState);

        // Spend and get nullifier
        const [spendProof, _] = proveSpend(paramsL4, token, 5n, rng);
        const nullifierHex = Buffer.from(spendProof.k.toBytes()).toString('hex');

        // Check for collision
        expect(nullifiers.has(nullifierHex)).toBe(false);
        nullifiers.add(nullifierHex);
      }

      // All 15 nullifiers should be unique
      expect(nullifiers.size).toBe(15);
    });

    it('rejects tampered refund (modified e value)', () => {
      const rng = makeRng(0x43);
      const ctx = group.scalarFromBigint(0n);

      // Issue and spend
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(params, issuerKeys.privateKey, request, 100n, ctx, rng);
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);
      const [spendProof, spendState] = proveSpend(params, token, 30n, rng);
      const refund = issueRefund(params, issuerKeys.privateKey, spendProof, 0n, rng);

      // Tamper with the refund e value
      const tamperedE = refund.eStar.add(group.scalarFromBigint(1n));
      const tamperedRefund = { ...refund, eStar: tamperedE };

      // Should fail to construct token
      expect(() =>
        constructRefundToken(params, issuerKeys.publicKey, spendProof, tamperedRefund, spendState)
      ).toThrow(ACTError);
    });

    it('rejects tampered refund (modified A point)', () => {
      const rng = makeRng(0x44);
      const ctx = group.scalarFromBigint(0n);

      // Issue and spend
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(params, issuerKeys.privateKey, request, 100n, ctx, rng);
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);
      const [spendProof, spendState] = proveSpend(params, token, 30n, rng);
      const refund = issueRefund(params, issuerKeys.privateKey, spendProof, 0n, rng);

      // Tamper with the A point
      const tamperedA = refund.AStar.multiply(group.scalarFromBigint(2n));
      const tamperedRefund = { ...refund, AStar: tamperedA };

      // Should fail to construct token
      expect(() =>
        constructRefundToken(params, issuerKeys.publicKey, spendProof, tamperedRefund, spendState)
      ).toThrow(ACTError);
    });

    it('rejects tampered refund (modified pok)', () => {
      const rng = makeRng(0x45);
      const ctx = group.scalarFromBigint(0n);

      // Issue and spend
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(params, issuerKeys.privateKey, request, 100n, ctx, rng);
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);
      const [spendProof, spendState] = proveSpend(params, token, 30n, rng);
      const refund = issueRefund(params, issuerKeys.privateKey, spendProof, 0n, rng);

      // Tamper with the pok
      const tamperedPok = new Uint8Array(refund.pok);
      tamperedPok[0] ^= 0xff;
      const tamperedRefund = { ...refund, pok: tamperedPok };

      // Should fail to construct token
      expect(() =>
        constructRefundToken(params, issuerKeys.publicKey, spendProof, tamperedRefund, spendState)
      ).toThrow(ACTError);
    });

    it('rejects zero e signature attack on issuance', () => {
      const rng = makeRng(0x46);
      const ctx = group.scalarFromBigint(0n);

      // Create legitimate issuance
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(params, issuerKeys.privateKey, request, 100n, ctx, rng);

      // Tamper: set e to zero
      const zeroE = group.scalarFromBigint(0n);
      const tamperedResponse = { ...response, e: zeroE };

      // Should reject (either ACTError or underlying crypto error)
      expect(() =>
        verifyIssuance(params, issuerKeys.publicKey, tamperedResponse, issueState)
      ).toThrow();
    });

    it('rejects identity point attack on A in issuance response', () => {
      const rng = makeRng(0x47);
      const ctx = group.scalarFromBigint(0n);

      // Create legitimate issuance
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(params, issuerKeys.privateKey, request, 100n, ctx, rng);

      // Tamper: set A to identity
      const identity = group.identity();
      const tamperedResponse = { ...response, A: identity };

      // Should reject (identity point creates invalid signature)
      expect(() =>
        verifyIssuance(params, issuerKeys.publicKey, tamperedResponse, issueState)
      ).toThrow(ACTError);
    });

    it('rejects identity A_prime in spend proof', () => {
      const rng = makeRng(0x48);
      const ctx = group.scalarFromBigint(0n);

      // Issue valid token
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(params, issuerKeys.privateKey, request, 100n, ctx, rng);
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);

      // Create spend proof
      const [spendProof, _] = proveSpend(params, token, 30n, rng);

      // Tamper: set A_prime to identity
      const tamperedProof = { ...spendProof, APrime: group.identity() };

      // Should reject - identity A_prime is invalid
      expect(() => verifySpendProof(params, issuerKeys.privateKey, tamperedProof)).toThrow(
        ACTError
      );
    });

    it('rejects tampered spend proof (modified pok)', () => {
      const rng = makeRng(0x49);
      const ctx = group.scalarFromBigint(0n);

      // Issue valid token
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(params, issuerKeys.privateKey, request, 100n, ctx, rng);
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);

      // Create spend proof
      const [spendProof, _] = proveSpend(params, token, 30n, rng);

      // Tamper with pok
      const tamperedPok = new Uint8Array(spendProof.pok);
      tamperedPok[0] ^= 0xff;
      const tamperedProof = { ...spendProof, pok: tamperedPok };

      // Should reject
      expect(() => verifySpendProof(params, issuerKeys.privateKey, tamperedProof)).toThrow(
        ACTError
      );
    });

    it('rejects tampered spend amount', () => {
      const rng = makeRng(0x4a);
      const ctx = group.scalarFromBigint(0n);

      // Issue valid token
      const [request, issueState] = issueRequest(params, ctx, rng);
      const response = issueResponse(params, issuerKeys.privateKey, request, 100n, ctx, rng);
      const token = verifyIssuance(params, issuerKeys.publicKey, response, issueState);

      // Create spend proof for 30
      const [spendProof, _] = proveSpend(params, token, 30n, rng);

      // Tamper: claim we're only spending 10
      const tamperedProof = { ...spendProof, s: 10n };

      // Should reject - commitment doesn't match claimed amount
      expect(() => verifySpendProof(params, issuerKeys.privateKey, tamperedProof)).toThrow(
        ACTError
      );
    });
  });
});
