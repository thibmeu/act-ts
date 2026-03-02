/**
 * Test Vector Generation for ACT VNEXT (TLS wire format)
 *
 * Generates deterministic test vectors using SeededPRNGForTestingOnly.
 * Vectors are written to test/vectors/testACT_vnext.json and verified on CI.
 *
 * Run with: npm test -- --run generate-vectors-vnext
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
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
  encodeIssuanceRequest,
  decodeIssuanceRequest,
  encodeIssuanceResponse,
  decodeIssuanceResponse,
  encodeSpendProof,
  decodeSpendProof,
  encodeRefund,
  decodeRefund,
  encodeCreditToken,
  decodeCreditToken,
  encodePrivateKey,
  encodePublicKey,
  SeededPRNGForTestingOnly,
  toHex,
  type SystemParams,
  type KeyPair,
  type CreditToken,
  type PRNG,
} from '../src/index-vnext.js';

/** Convert Uint8Array to hex string */
function bytesToHex(bytes: Uint8Array): string {
  return toHex(bytes);
}

/** Convert hex string to Uint8Array */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Vector generation configuration.
 * Uses deterministic seeds for reproducibility.
 */
const CONFIG = {
  L: 8,
  domainSeparator: 'ACT-v1:test:vectors:vnext:2026-03-02',
  // Seeds are 32-byte values absorbed into SHAKE128 sponge
  seeds: {
    keyGen: hexToBytes('0001020304050607080910111213141516171819202122232425262728293031'),
    issuance: hexToBytes('1001020304050607080910111213141516171819202122232425262728293031'),
    spend: hexToBytes('2001020304050607080910111213141516171819202122232425262728293031'),
    refund: hexToBytes('3001020304050607080910111213141516171819202122232425262728293031'),
  },
  creditAmount: 100n,
  spendAmount: 30n,
  refundAmount: 10n,
};

interface TestVectors {
  description: string;
  format: string;
  ciphersuite: string;
  generated: string;
  parameters: {
    domain_separator: string;
    L: number;
  };
  seeds: {
    key_gen: string;
    issuance: string;
    spend: string;
    refund: string;
  };
  key_generation: {
    private_key: string;
    public_key: string;
  };
  issuance: {
    credit_amount: string;
    ctx: string;
    issuance_request: string;
    issuance_response: string;
    credit_token: string;
  };
  spending: {
    spend_amount: string;
    nullifier: string;
    spend_proof: string;
  };
  refund: {
    refund_amount: string;
    refund: string;
    new_nullifier: string;
    new_credit_token: string;
    remaining_balance: string;
  };
}

describe('ACT VNEXT Vector Generation', () => {
  const group = ristretto255;
  let params: SystemParams;
  let keys: KeyPair;
  let token: CreditToken;
  let vectors: TestVectors;

  // Intermediate values for building vectors
  let issuanceCtx: ReturnType<typeof group.scalarFromBigint>;
  let issuanceRequestBytes: Uint8Array;
  let issuanceResponseBytes: Uint8Array;
  let creditTokenBytes: Uint8Array;
  let spendProofBytes: Uint8Array;
  let refundBytes: Uint8Array;
  let newTokenBytes: Uint8Array;
  let nullifierHex: string;
  let newNullifierHex: string;

  it('generates parameters', () => {
    params = generateParameters(group, CONFIG.domainSeparator, CONFIG.L);
    expect(params.L).toBe(CONFIG.L);
  });

  it('generates keys deterministically', () => {
    const rng = new SeededPRNGForTestingOnly(CONFIG.seeds.keyGen);
    keys = keyGen(group, rng);

    const skBytes = encodePrivateKey(keys.privateKey);
    const pkBytes = encodePublicKey(keys.publicKey);

    expect(skBytes.length).toBe(32);
    expect(pkBytes.length).toBe(32);
  });

  it('performs issuance deterministically', () => {
    const rng = new SeededPRNGForTestingOnly(CONFIG.seeds.issuance);

    // Use a fixed context
    issuanceCtx = group.scalarFromBigint(0x1234n);

    // Client creates request
    const [request, state] = issueRequest(params, issuanceCtx, rng);
    issuanceRequestBytes = encodeIssuanceRequest(request);

    // Issuer creates response
    const response = issueResponse(
      params,
      keys.privateKey,
      request,
      CONFIG.creditAmount,
      issuanceCtx,
      rng
    );
    issuanceResponseBytes = encodeIssuanceResponse(group, { ...response, ctx: issuanceCtx });

    // Client verifies and gets token
    token = verifyIssuance(params, keys.publicKey, response, state);
    creditTokenBytes = encodeCreditToken(group, token);

    expect(token.c).toBe(CONFIG.creditAmount);

    // Verify roundtrip
    const decodedReq = decodeIssuanceRequest(group, issuanceRequestBytes);
    expect(decodedReq.K.equals(request.K)).toBe(true);

    const decodedResp = decodeIssuanceResponse(group, issuanceResponseBytes);
    expect(decodedResp.A.equals(response.A)).toBe(true);
    expect(decodedResp.c).toBe(response.c);

    const decodedToken = decodeCreditToken(group, creditTokenBytes);
    expect(decodedToken.c).toBe(token.c);
  });

  it('performs spend deterministically', () => {
    const rng = new SeededPRNGForTestingOnly(CONFIG.seeds.spend);

    // Create spend proof
    const [spendProof, spendState] = proveSpend(params, token, CONFIG.spendAmount, rng);
    spendProofBytes = encodeSpendProof(group, spendProof);
    nullifierHex = bytesToHex(spendProof.k.toBytes());

    // Verify spend proof
    verifySpendProof(params, keys.privateKey, spendProof);

    expect(spendProof.s).toBe(CONFIG.spendAmount);

    // Verify roundtrip
    const decodedProof = decodeSpendProof(group, params.L, spendProofBytes);
    expect(decodedProof.s).toBe(spendProof.s);
    expect(decodedProof.APrime.equals(spendProof.APrime)).toBe(true);

    // Store spendState for refund test (accessed via closure)
    (globalThis as Record<string, unknown>).__spendState = spendState;
    (globalThis as Record<string, unknown>).__spendProof = spendProof;
  });

  it('performs refund deterministically', () => {
    const rng = new SeededPRNGForTestingOnly(CONFIG.seeds.refund);

    const spendProof = (globalThis as Record<string, unknown>).__spendProof as ReturnType<
      typeof proveSpend
    >[0];
    const spendState = (globalThis as Record<string, unknown>).__spendState as ReturnType<
      typeof proveSpend
    >[1];

    // Issue refund
    const refund = issueRefund(params, keys.privateKey, spendProof, CONFIG.refundAmount, rng);
    refundBytes = encodeRefund(group, refund);

    expect(refund.t).toBe(CONFIG.refundAmount);

    // Construct new token
    const newToken = constructRefundToken(params, keys.publicKey, spendProof, refund, spendState);
    newTokenBytes = encodeCreditToken(group, newToken);
    newNullifierHex = bytesToHex(newToken.k.toBytes());

    // Expected balance: c - s + t = 100 - 30 + 10 = 80
    expect(newToken.c).toBe(80n);

    // Verify roundtrip
    const decodedRefund = decodeRefund(group, refundBytes);
    expect(decodedRefund.t).toBe(refund.t);
    expect(decodedRefund.AStar.equals(refund.AStar)).toBe(true);

    const decodedNewToken = decodeCreditToken(group, newTokenBytes);
    expect(decodedNewToken.c).toBe(newToken.c);

    // Cleanup globals
    delete (globalThis as Record<string, unknown>).__spendState;
    delete (globalThis as Record<string, unknown>).__spendProof;
  });

  it('builds and writes vector file', () => {
    vectors = {
      description: 'ACT VNEXT Test Vectors (TLS wire format)',
      format: 'TLS presentation language (RFC 8446 Section 3)',
      ciphersuite: 'ACT_ristretto255_SHAKE128',
      generated: new Date().toISOString().split('T')[0]!,
      parameters: {
        domain_separator: CONFIG.domainSeparator,
        L: CONFIG.L,
      },
      seeds: {
        key_gen: bytesToHex(CONFIG.seeds.keyGen),
        issuance: bytesToHex(CONFIG.seeds.issuance),
        spend: bytesToHex(CONFIG.seeds.spend),
        refund: bytesToHex(CONFIG.seeds.refund),
      },
      key_generation: {
        private_key: bytesToHex(encodePrivateKey(keys.privateKey)),
        public_key: bytesToHex(encodePublicKey(keys.publicKey)),
      },
      issuance: {
        credit_amount: CONFIG.creditAmount.toString(),
        ctx: bytesToHex(issuanceCtx.toBytes()),
        issuance_request: bytesToHex(issuanceRequestBytes),
        issuance_response: bytesToHex(issuanceResponseBytes),
        credit_token: bytesToHex(creditTokenBytes),
      },
      spending: {
        spend_amount: CONFIG.spendAmount.toString(),
        nullifier: nullifierHex,
        spend_proof: bytesToHex(spendProofBytes),
      },
      refund: {
        refund_amount: CONFIG.refundAmount.toString(),
        refund: bytesToHex(refundBytes),
        new_nullifier: newNullifierHex,
        new_credit_token: bytesToHex(newTokenBytes),
        remaining_balance: '80',
      },
    };

    // Write to file
    const vectorPath = path.join(import.meta.dirname, 'vectors', 'testACT_vnext.json');
    fs.writeFileSync(vectorPath, JSON.stringify(vectors, null, 2) + '\n');

    console.log(`Vectors written to ${vectorPath}`);
    expect(vectors.ciphersuite).toBe('ACT_ristretto255_SHAKE128');
  });
});

describe('ACT VNEXT Vector Verification', () => {
  const group = ristretto255;
  let vectors: TestVectors;

  it('loads vectors from file', () => {
    const vectorPath = path.join(import.meta.dirname, 'vectors', 'testACT_vnext.json');
    vectors = JSON.parse(fs.readFileSync(vectorPath, 'utf-8')) as TestVectors;
    expect(vectors.format).toContain('TLS');
  });

  it('verifies issuance request decodes correctly', () => {
    const params = generateParameters(
      group,
      vectors.parameters.domain_separator,
      vectors.parameters.L
    );
    const reqBytes = hexToBytes(vectors.issuance.issuance_request);
    const req = decodeIssuanceRequest(group, reqBytes);

    expect(req.K.equals(group.identity())).toBe(false);
    expect(req.pok.length).toBeGreaterThan(0);

    // Re-encode and verify
    const reencoded = encodeIssuanceRequest(req);
    expect(bytesToHex(reencoded)).toBe(vectors.issuance.issuance_request);
  });

  it('verifies issuance response decodes correctly', () => {
    const respBytes = hexToBytes(vectors.issuance.issuance_response);
    const resp = decodeIssuanceResponse(group, respBytes);

    expect(resp.A.equals(group.identity())).toBe(false);
    expect(resp.c).toBe(BigInt(vectors.issuance.credit_amount));

    // Re-encode and verify
    const reencoded = encodeIssuanceResponse(group, resp);
    expect(bytesToHex(reencoded)).toBe(vectors.issuance.issuance_response);
  });

  it('verifies credit token decodes correctly', () => {
    const tokenBytes = hexToBytes(vectors.issuance.credit_token);
    const token = decodeCreditToken(group, tokenBytes);

    expect(token.c).toBe(BigInt(vectors.issuance.credit_amount));

    // Re-encode and verify
    const reencoded = encodeCreditToken(group, token);
    expect(bytesToHex(reencoded)).toBe(vectors.issuance.credit_token);
  });

  it('verifies spend proof decodes correctly', () => {
    const proofBytes = hexToBytes(vectors.spending.spend_proof);
    const proof = decodeSpendProof(group, vectors.parameters.L, proofBytes);

    expect(proof.s).toBe(BigInt(vectors.spending.spend_amount));
    expect(bytesToHex(proof.k.toBytes())).toBe(vectors.spending.nullifier);

    // Re-encode and verify
    const reencoded = encodeSpendProof(group, proof);
    expect(bytesToHex(reencoded)).toBe(vectors.spending.spend_proof);
  });

  it('verifies refund decodes correctly', () => {
    const refundBytes = hexToBytes(vectors.refund.refund);
    const refund = decodeRefund(group, refundBytes);

    expect(refund.t).toBe(BigInt(vectors.refund.refund_amount));

    // Re-encode and verify
    const reencoded = encodeRefund(group, refund);
    expect(bytesToHex(reencoded)).toBe(vectors.refund.refund);
  });

  it('verifies new credit token decodes correctly', () => {
    const tokenBytes = hexToBytes(vectors.refund.new_credit_token);
    const token = decodeCreditToken(group, tokenBytes);

    expect(token.c).toBe(BigInt(vectors.refund.remaining_balance));
    expect(bytesToHex(token.k.toBytes())).toBe(vectors.refund.new_nullifier);

    // Re-encode and verify
    const reencoded = encodeCreditToken(group, token);
    expect(bytesToHex(reencoded)).toBe(vectors.refund.new_credit_token);
  });

  it('verifies full protocol flow with vectors', () => {
    const params = generateParameters(
      group,
      vectors.parameters.domain_separator,
      vectors.parameters.L
    );

    // Load keys
    const skBytes = hexToBytes(vectors.key_generation.private_key);
    const pkBytes = hexToBytes(vectors.key_generation.public_key);
    const sk = { x: group.scalarFromBytes(skBytes) };
    const pk = { W: group.elementFromBytes(pkBytes) };

    // Load credit token
    const tokenBytes = hexToBytes(vectors.issuance.credit_token);
    const token = decodeCreditToken(group, tokenBytes);

    // Load spend proof
    const proofBytes = hexToBytes(vectors.spending.spend_proof);
    const proof = decodeSpendProof(group, vectors.parameters.L, proofBytes);

    // Verify spend proof
    expect(() => verifySpendProof(params, sk, proof)).not.toThrow();

    // Load refund
    const refundBytes = hexToBytes(vectors.refund.refund);
    const refund = decodeRefund(group, refundBytes);

    // Verify refund values
    expect(refund.t).toBe(BigInt(vectors.refund.refund_amount));
  });
});
