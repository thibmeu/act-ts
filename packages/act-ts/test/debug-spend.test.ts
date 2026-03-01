/**
 * Debug test for spend proof ABar computation
 */

import { describe, it, expect } from 'vitest';
import {
  ristretto255,
  generateParameters,
  keyGen,
  issueRequest,
  issueResponse,
  verifyIssuance,
  proveSpend,
  verifySpendProof,
  SeededPRNG,
} from '../src/index-vnext.js';

describe('Debug Spend', () => {
  it('verifies ABar computation matches', () => {
    const group = ristretto255;
    const seed = new Uint8Array(32);
    seed[0] = 0x99;
    const rng = new SeededPRNG(seed);

    const params = generateParameters(group, 'ACT-v1:test:debug:local:2026', 4);
    const { privateKey: sk, publicKey: pk } = keyGen(group, rng);

    // Issue a token
    const ctx = group.scalarFromBigint(0x1234n);
    const [request, issueState] = issueRequest(params, ctx, rng);
    const response = issueResponse(params, sk, request, 10n, ctx, rng);
    const token = verifyIssuance(params, pk, response, issueState);

    // Manual spend proof computation to debug
    const { A, e, k, r, c } = token;
    const { H1, H2, H3, H4 } = params;
    const G = group.generator();
    const one = group.scalarFromBigint(1n);
    const cScalar = group.scalarFromBigint(c);

    // Random scalars
    const r1 = group.hashToScalar(rng.randomBytes(48));
    const r2 = group.hashToScalar(rng.randomBytes(48));

    // B = G + c*H1 + k*H2 + r*H3 + ctx*H4
    const B = group.msm([one, cScalar, k, r, ctx], [G, H1, H2, H3, H4]);

    // Randomize
    const APrime = A.multiply(r1.mul(r2));
    const BBar = B.multiply(r1);

    // Prover's ABar = -e*A' + r2*BBar
    const proverABar = APrime.multiply(e).negate().add(BBar.multiply(r2));

    // Verifier's ABar = A' * sk
    const verifierABar = APrime.multiply(sk.x);

    // These should be equal!
    console.log('Prover ABar:', Buffer.from(proverABar.toBytes()).toString('hex'));
    console.log('Verifier ABar:', Buffer.from(verifierABar.toBytes()).toString('hex'));
    console.log('Equal:', proverABar.equals(verifierABar));

    // Also verify the BBS signature
    // A * (sk + e) should equal B
    const shouldBeB = A.multiply(sk.x.add(e));
    console.log('B:', Buffer.from(B.toBytes()).toString('hex'));
    console.log('A*(sk+e):', Buffer.from(shouldBeB.toBytes()).toString('hex'));
    console.log('BBS valid:', B.equals(shouldBeB));

    expect(B.equals(shouldBeB)).toBe(true);
    expect(proverABar.equals(verifierABar)).toBe(true);
  });

  it('runs full spend proof flow L=4', () => {
    const group = ristretto255;
    const seed = new Uint8Array(32);
    seed[0] = 0xaa;
    const rng = new SeededPRNG(seed);

    const params = generateParameters(group, 'ACT-v1:test:debug:local:2026', 4);
    const { privateKey: sk, publicKey: pk } = keyGen(group, rng);

    // Issue a token
    const ctx = group.scalarFromBigint(0n);
    const [request, issueState] = issueRequest(params, ctx, rng);
    const response = issueResponse(params, sk, request, 10n, ctx, rng);
    const token = verifyIssuance(params, pk, response, issueState);

    console.log('Token c:', token.c);

    // Try to spend
    const [spendProof, spendState] = proveSpend(params, token, 5n, rng);
    console.log('Spend proof created');
    console.log('pok length:', spendProof.pok.length);

    verifySpendProof(params, sk, spendProof);
    console.log('Spend proof verified!');
  });

  it.each([4, 5, 6, 7, 8])('runs full spend proof flow L=%i ctx=0', (L) => {
    const group = ristretto255;
    const seed = new Uint8Array(32);
    seed[0] = 0xbb + L;
    const rng = new SeededPRNG(seed);

    const maxValue = (1n << BigInt(L)) - 1n;
    const creditAmount = maxValue > 10n ? 10n : maxValue;
    const spendAmount = creditAmount > 3n ? 3n : 1n;

    const params = generateParameters(group, 'ACT-v1:test:debug:local:2026', L);
    const { privateKey: sk, publicKey: pk } = keyGen(group, rng);

    // Issue a token
    const ctx = group.scalarFromBigint(0n);
    const [request, issueState] = issueRequest(params, ctx, rng);
    const response = issueResponse(params, sk, request, creditAmount, ctx, rng);
    const token = verifyIssuance(params, pk, response, issueState);

    // Try to spend
    const [spendProof, _] = proveSpend(params, token, spendAmount, rng);
    verifySpendProof(params, sk, spendProof);
  });

  it.each([4, 5, 6, 7, 8])('runs full spend proof flow L=%i ctx=0x5678', (L) => {
    const group = ristretto255;
    const seed = new Uint8Array(32);
    seed[0] = 0xcc + L;
    const rng = new SeededPRNG(seed);

    const maxValue = (1n << BigInt(L)) - 1n;
    const creditAmount = maxValue > 10n ? 10n : maxValue;
    const spendAmount = creditAmount > 3n ? 3n : 1n;

    const params = generateParameters(group, 'ACT-v1:test:debug:local:2026', L);
    const { privateKey: sk, publicKey: pk } = keyGen(group, rng);

    // Issue a token with non-zero ctx
    const ctx = group.scalarFromBigint(0x5678n);
    const [request, issueState] = issueRequest(params, ctx, rng);
    const response = issueResponse(params, sk, request, creditAmount, ctx, rng);
    const token = verifyIssuance(params, pk, response, issueState);

    // Try to spend
    const [spendProof, _] = proveSpend(params, token, spendAmount, rng);
    verifySpendProof(params, sk, spendProof);
  });

  it.each([1, 2, 3])('runs full spend proof flow L=%i (small L)', (L) => {
    const group = ristretto255;
    const seed = new Uint8Array(32);
    seed[0] = 0xdd + L;
    const rng = new SeededPRNG(seed);

    const maxValue = (1n << BigInt(L)) - 1n;
    const creditAmount = maxValue;
    const spendAmount = creditAmount > 0n ? 1n : 0n;

    const params = generateParameters(group, 'ACT-v1:test:debug:smallL:2026', L);
    const { privateKey: sk, publicKey: pk } = keyGen(group, rng);

    // Issue a token
    const ctx = group.scalarFromBigint(0n);
    const [request, issueState] = issueRequest(params, ctx, rng);
    const response = issueResponse(params, sk, request, creditAmount, ctx, rng);
    const token = verifyIssuance(params, pk, response, issueState);

    // Try to spend
    const [spendProof, _] = proveSpend(params, token, spendAmount, rng);
    verifySpendProof(params, sk, spendProof);
  });
});
