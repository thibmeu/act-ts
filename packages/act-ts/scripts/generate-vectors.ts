#!/usr/bin/env npx tsx
/**
 * Test Vector Generation for ACT VNEXT (TLS wire format)
 *
 * Generates deterministic test vectors using SeededPRNGForTestingOnly.
 * Vectors are written to test/vectors/draft-schlesinger-02.json.
 *
 * Run with: npx tsx scripts/generate-vectors.ts
 */

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
  encodeIssuanceResponse,
  encodeSpendProof,
  encodeRefund,
  encodeCreditToken,
  encodePrivateKey,
  encodePublicKey,
  SeededPRNGForTestingOnly,
  toHex,
} from '../src/index-vnext.js';

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

function generateVectors(): TestVectors {
  const group = ristretto255;

  // Generate parameters
  const params = generateParameters(group, CONFIG.domainSeparator, CONFIG.L);
  console.log('Generated parameters with L =', params.L);

  // Generate keys deterministically
  const keyGenRng = new SeededPRNGForTestingOnly(CONFIG.seeds.keyGen);
  const keys = keyGen(group, keyGenRng);
  const skBytes = encodePrivateKey(keys.privateKey);
  const pkBytes = encodePublicKey(keys.publicKey);
  console.log('Generated key pair');

  // Issuance
  const issuanceRng = new SeededPRNGForTestingOnly(CONFIG.seeds.issuance);
  const issuanceCtx = group.scalarFromBigint(0x1234n);

  const [request, state] = issueRequest(params, issuanceCtx, issuanceRng);
  const issuanceRequestBytes = encodeIssuanceRequest(request);

  const response = issueResponse(
    params,
    keys.privateKey,
    request,
    CONFIG.creditAmount,
    issuanceCtx,
    issuanceRng
  );
  const issuanceResponseBytes = encodeIssuanceResponse(group, { ...response, ctx: issuanceCtx });

  const token = verifyIssuance(params, keys.publicKey, response, state);
  const creditTokenBytes = encodeCreditToken(group, token);
  console.log('Generated issuance (credit =', token.c, ')');

  // Spending
  const spendRng = new SeededPRNGForTestingOnly(CONFIG.seeds.spend);
  const [spendProof, spendState] = proveSpend(params, token, CONFIG.spendAmount, spendRng);
  const spendProofBytes = encodeSpendProof(group, spendProof);
  const nullifierHex = toHex(spendProof.k.toBytes());

  // Verify spend proof
  verifySpendProof(params, keys.privateKey, spendProof);
  console.log('Generated spend proof (amount =', spendProof.s, ')');

  // Refund
  const refundRng = new SeededPRNGForTestingOnly(CONFIG.seeds.refund);
  const refund = issueRefund(params, keys.privateKey, spendProof, CONFIG.refundAmount, refundRng);
  const refundBytes = encodeRefund(group, refund);

  const newToken = constructRefundToken(params, keys.publicKey, spendProof, refund, spendState);
  const newTokenBytes = encodeCreditToken(group, newToken);
  const newNullifierHex = toHex(newToken.k.toBytes());
  console.log('Generated refund (new balance =', newToken.c, ')');

  return {
    description: 'ACT VNEXT Test Vectors (TLS wire format)',
    format: 'TLS presentation language (RFC 8446 Section 3)',
    ciphersuite: 'ACT_ristretto255_SHAKE128',
    generated: new Date().toISOString().split('T')[0]!,
    parameters: {
      domain_separator: CONFIG.domainSeparator,
      L: CONFIG.L,
    },
    seeds: {
      key_gen: toHex(CONFIG.seeds.keyGen),
      issuance: toHex(CONFIG.seeds.issuance),
      spend: toHex(CONFIG.seeds.spend),
      refund: toHex(CONFIG.seeds.refund),
    },
    key_generation: {
      private_key: toHex(skBytes),
      public_key: toHex(pkBytes),
    },
    issuance: {
      credit_amount: CONFIG.creditAmount.toString(),
      ctx: toHex(issuanceCtx.toBytes()),
      issuance_request: toHex(issuanceRequestBytes),
      issuance_response: toHex(issuanceResponseBytes),
      credit_token: toHex(creditTokenBytes),
    },
    spending: {
      spend_amount: CONFIG.spendAmount.toString(),
      nullifier: nullifierHex,
      spend_proof: toHex(spendProofBytes),
    },
    refund: {
      refund_amount: CONFIG.refundAmount.toString(),
      refund: toHex(refundBytes),
      new_nullifier: newNullifierHex,
      new_credit_token: toHex(newTokenBytes),
      remaining_balance: '80',
    },
  };
}

// Main
const vectors = generateVectors();
const vectorPath = path.join(
  import.meta.dirname,
  '..',
  'test',
  'vectors',
  'draft-schlesinger-02.json'
);
fs.writeFileSync(vectorPath, JSON.stringify(vectors, null, 2) + '\n');
console.log(`\nVectors written to ${vectorPath}`);
