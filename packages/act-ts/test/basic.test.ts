/**
 * Basic ACT tests
 *
 * Tests core functionality: params, keygen, issuance, spending
 */

import { describe, it, expect } from 'vitest';
import {
  generateParameters,
  createDomainSeparator,
  validateDomainSeparator,
  keyGen,
  privateKeyToBytes,
  privateKeyFromBytes,
  publicKeyToBytes,
  publicKeyFromBytes,
  derivePublicKey,
  issueRequest,
  issueResponse,
  verifyIssuance,
  proveSpend,
  verifySpendProof,
  issueRefund,
  constructRefundToken,
  group,
  ACTError,
  ACTErrorCode,
  toHex,
} from '../src/index.js';

describe('SystemParams', () => {
  it('generates deterministic parameters from domain separator', () => {
    const domain = 'ACT-v1:test:api:prod:2024-01-15';
    const params1 = generateParameters(domain, 64);
    const params2 = generateParameters(domain, 64);

    expect(params1.H1.equals(params2.H1)).toBe(true);
    expect(params1.H2.equals(params2.H2)).toBe(true);
    expect(params1.H3.equals(params2.H3)).toBe(true);
    expect(params1.H4.equals(params2.H4)).toBe(true);
    expect(params1.L).toBe(64);
  });

  it('generates different parameters for different domains', () => {
    const params1 = generateParameters('ACT-v1:org1:svc:prod:2024-01-15', 64);
    const params2 = generateParameters('ACT-v1:org2:svc:prod:2024-01-15', 64);

    expect(params1.H1.equals(params2.H1)).toBe(false);
  });

  it('enforces L constraint [1, 128]', () => {
    expect(() => generateParameters('ACT-v1:t:s:d:v', 0)).toThrow(ACTError);
    expect(() => generateParameters('ACT-v1:t:s:d:v', 129)).toThrow(ACTError);
    expect(() => generateParameters('ACT-v1:t:s:d:v', 1)).not.toThrow();
    expect(() => generateParameters('ACT-v1:t:s:d:v', 128)).not.toThrow();
  });

  it('validates domain separator format', () => {
    expect(validateDomainSeparator('ACT-v1:org:svc:deploy:2024-01-15')).toBe(true);
    expect(validateDomainSeparator('invalid')).toBe(false);
    expect(validateDomainSeparator('ACT-v1:a:b:c:')).toBe(false); // empty component
  });

  it('creates properly formatted domain separator', () => {
    const domain = createDomainSeparator('acme', 'api', 'prod', '2024-01-15');
    expect(domain).toBe('ACT-v1:acme:api:prod:2024-01-15');
    expect(validateDomainSeparator(domain)).toBe(true);
  });

  it('rejects colons in domain separator components', () => {
    expect(() => createDomainSeparator('ac:me', 'api', 'prod', '2024')).toThrow();
  });
});

describe('KeyGen', () => {
  it('generates valid key pair', () => {
    const { privateKey, publicKey } = keyGen();

    expect(privateKey.x).toBeDefined();
    expect(publicKey.W).toBeDefined();
    expect(publicKey.W.isIdentity()).toBe(false);
  });

  it('derives public key from private key', () => {
    const { privateKey, publicKey } = keyGen();
    const derived = derivePublicKey(privateKey);

    expect(derived.W.equals(publicKey.W)).toBe(true);
  });

  it('serializes and deserializes private key', () => {
    const { privateKey } = keyGen();
    const bytes = privateKeyToBytes(privateKey);
    const restored = privateKeyFromBytes(bytes);

    expect(restored.x.equals(privateKey.x)).toBe(true);
  });

  it('serializes and deserializes public key', () => {
    const { publicKey } = keyGen();
    const bytes = publicKeyToBytes(publicKey);
    const restored = publicKeyFromBytes(bytes);

    expect(restored.W.equals(publicKey.W)).toBe(true);
  });
});

describe('Issuance', () => {
  const params = generateParameters('ACT-v1:test:api:dev:2024-01-01', 64);
  const { privateKey, publicKey } = keyGen();

  it('completes issuance round-trip', () => {
    const ctx = group.randomScalar();
    const creditAmount = 1000n;

    // Client creates request
    const [request, state] = issueRequest(params);

    // Issuer creates response
    const response = issueResponse(params, privateKey, request, creditAmount, ctx);

    // Client verifies and gets token
    const token = verifyIssuance(params, publicKey, request, response, state);

    expect(token.c).toBe(creditAmount);
    expect(token.ctx.equals(ctx)).toBe(true);
    expect(token.k.equals(state.k)).toBe(true);
    expect(token.r.equals(state.r)).toBe(true);
  });

  it('rejects invalid request proof', () => {
    const ctx = group.randomScalar();

    // Create valid request
    const [request, _state] = issueRequest(params);

    // Tamper with request
    const badRequest = {
      ...request,
      kBar: group.randomScalar(), // Wrong response
    };

    expect(() => issueResponse(params, privateKey, badRequest, 100n, ctx)).toThrow(ACTError);
  });

  it('rejects invalid response proof', () => {
    const ctx = group.randomScalar();

    const [request, state] = issueRequest(params);
    const response = issueResponse(params, privateKey, request, 100n, ctx);

    // Tamper with response
    const badResponse = {
      ...response,
      z: group.randomScalar(), // Wrong response
    };

    expect(() => verifyIssuance(params, publicKey, request, badResponse, state)).toThrow(ACTError);
  });

  it('rejects credit amount exceeding 2^L', () => {
    const ctx = group.randomScalar();
    const [request, _state] = issueRequest(params);

    // params.L = 64, so max is 2^64 - 1
    const tooBig = 1n << 64n;

    expect(() => issueResponse(params, privateKey, request, tooBig, ctx)).toThrow(ACTError);
  });

  it('rejects zero credit amount', () => {
    const ctx = group.randomScalar();
    const [request, _state] = issueRequest(params);

    expect(() => issueResponse(params, privateKey, request, 0n, ctx)).toThrow(ACTError);
  });
});

describe('Spending', () => {
  const params = generateParameters('ACT-v1:test:api:dev:2024-01-01', 16); // Small L for faster tests
  const { privateKey, publicKey } = keyGen();

  function issueToken(amount: bigint) {
    const ctx = group.randomScalar();
    const [request, state] = issueRequest(params);
    const response = issueResponse(params, privateKey, request, amount, ctx);
    return verifyIssuance(params, publicKey, request, response, state);
  }

  it('creates and verifies spend proof', () => {
    const token = issueToken(100n);
    const spendAmount = 30n;

    const [proof, _state] = proveSpend(params, token, spendAmount);

    expect(proof.s).toBe(spendAmount);
    expect(proof.k.equals(token.k)).toBe(true);

    // Verify proof
    const valid = verifySpendProof(params, privateKey, proof);
    expect(valid).toBe(true);
  });

  it('issues and constructs refund token', () => {
    const token = issueToken(100n);
    const spendAmount = 30n;

    const [proof, spendState] = proveSpend(params, token, spendAmount);
    verifySpendProof(params, privateKey, proof);

    // Issue refund with no partial return
    const refund = issueRefund(params, privateKey, proof, 0n);

    // Client constructs new token
    const newToken = constructRefundToken(params, publicKey, proof, refund, spendState);

    // New balance should be 100 - 30 = 70
    expect(newToken.c).toBe(70n);
  });

  it('issues refund with partial return', () => {
    const token = issueToken(100n);
    const spendAmount = 50n;
    const returnAmount = 20n;

    const [proof, spendState] = proveSpend(params, token, spendAmount);
    verifySpendProof(params, privateKey, proof);

    // Return 20 of the 50 spent
    const refund = issueRefund(params, privateKey, proof, returnAmount);
    const newToken = constructRefundToken(params, publicKey, proof, refund, spendState);

    // New balance should be 100 - 50 + 20 = 70
    expect(newToken.c).toBe(70n);
  });

  it('allows zero spend (re-anonymization)', () => {
    const token = issueToken(100n);

    const [proof, spendState] = proveSpend(params, token, 0n);
    verifySpendProof(params, privateKey, proof);

    const refund = issueRefund(params, privateKey, proof, 0n);
    const newToken = constructRefundToken(params, publicKey, proof, refund, spendState);

    // Balance unchanged
    expect(newToken.c).toBe(100n);
    // But new nullifier
    expect(newToken.k.equals(token.k)).toBe(false);
  });

  it('allows spending full balance', () => {
    const token = issueToken(100n);

    const [proof, spendState] = proveSpend(params, token, 100n);
    verifySpendProof(params, privateKey, proof);

    const refund = issueRefund(params, privateKey, proof, 0n);
    const newToken = constructRefundToken(params, publicKey, proof, refund, spendState);

    expect(newToken.c).toBe(0n);
  });

  it('rejects spending more than balance', () => {
    const token = issueToken(100n);

    expect(() => proveSpend(params, token, 101n)).toThrow(ACTError);
  });

  it('rejects return amount greater than spend amount', () => {
    const token = issueToken(100n);

    const [proof, _state] = proveSpend(params, token, 30n);
    verifySpendProof(params, privateKey, proof);

    expect(() => issueRefund(params, privateKey, proof, 31n)).toThrow(ACTError);
  });
});

describe('Double-spend prevention', () => {
  const params = generateParameters('ACT-v1:test:api:dev:2024-01-01', 16);
  const { privateKey, publicKey } = keyGen();
  const usedNullifiers = new Set<string>();

  it('detects double-spend via nullifier', () => {
    // Issue token
    const ctx = group.randomScalar();
    const [request, state] = issueRequest(params);
    const response = issueResponse(params, privateKey, request, 100n, ctx);
    const token = verifyIssuance(params, publicKey, request, response, state);

    // First spend
    const [proof1, _state1] = proveSpend(params, token, 50n);

    // Manually track nullifier
    const nullifierKey = toHex(proof1.k.toBytes());
    expect(usedNullifiers.has(nullifierKey)).toBe(false);

    verifySpendProof(params, privateKey, proof1);
    usedNullifiers.add(nullifierKey);

    // Second spend with same token (same nullifier)
    const [proof2, _state2] = proveSpend(params, token, 30n);

    // Same nullifier should be detected
    const nullifier2Key = toHex(proof2.k.toBytes());
    expect(nullifier2Key).toBe(nullifierKey);
    expect(usedNullifiers.has(nullifier2Key)).toBe(true);
  });
});
