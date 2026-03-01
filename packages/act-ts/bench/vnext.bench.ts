/**
 * Benchmarks for ACT VNEXT implementation
 *
 * Run with: npx vitest bench
 */

import { bench, describe } from 'vitest';
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
  SeededPRNG,
  type SystemParams,
  type KeyPair,
  type CreditToken,
  type SpendProof,
  type SpendState,
} from '../src/index-vnext.js';

// Shared setup - created once per benchmark suite
const group = ristretto255;

function createParams(L: number): SystemParams {
  return generateParameters(group, `ACT-v1:bench:test:local:2026`, L);
}

function createRng(seed: number): SeededPRNG {
  const seedBytes = new Uint8Array(32);
  seedBytes[0] = seed & 0xff;
  seedBytes[1] = (seed >> 8) & 0xff;
  return new SeededPRNG(seedBytes);
}

// Pre-compute params for different L values to avoid setup overhead in benchmarks
const paramsL8 = createParams(8);
const paramsL16 = createParams(16);
const paramsL32 = createParams(32);
const paramsL64 = createParams(64);
const paramsL128 = createParams(128);

// Pre-generate issuer keys
const issuerKeysL8 = keyGen(group, createRng(0x42));
const issuerKeysL16 = keyGen(group, createRng(0x43));
const issuerKeysL32 = keyGen(group, createRng(0x44));
const issuerKeysL64 = keyGen(group, createRng(0x45));
const issuerKeysL128 = keyGen(group, createRng(0x46));

// Helper to create a token for spend benchmarks
function createToken(
  params: SystemParams,
  keys: KeyPair,
  creditAmount: bigint,
  seed: number
): CreditToken {
  const rng = createRng(seed);
  const ctx = group.scalarFromBigint(0n);
  const [request, issueState] = issueRequest(params, ctx, rng);
  const response = issueResponse(params, keys.privateKey, request, creditAmount, ctx, rng);
  return verifyIssuance(params, keys.publicKey, response, issueState);
}

// Helper to create spend proof for refund benchmarks
function createSpendProof(
  params: SystemParams,
  keys: KeyPair,
  token: CreditToken,
  spendAmount: bigint,
  seed: number
): [SpendProof, SpendState] {
  const rng = createRng(seed);
  return proveSpend(params, token, spendAmount, rng);
}

describe('Key Generation', () => {
  bench('keyGen', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    keyGen(group, rng);
  });
});

describe('Parameter Generation', () => {
  bench('generateParameters L=8', () => {
    generateParameters(group, `ACT-v1:bench:unique:${Math.random()}`, 8);
  });

  bench('generateParameters L=64', () => {
    generateParameters(group, `ACT-v1:bench:unique:${Math.random()}`, 64);
  });
});

describe('Issuance Request', () => {
  bench('issueRequest', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    const ctx = group.scalarFromBigint(0n);
    issueRequest(paramsL8, ctx, rng);
  });
});

describe('Issuance Response (by L)', () => {
  // Pre-create requests for each benchmark
  const ctx = group.scalarFromBigint(0n);

  bench('issueResponse L=8', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    const [request] = issueRequest(paramsL8, ctx, rng);
    issueResponse(paramsL8, issuerKeysL8.privateKey, request, 100n, ctx, rng);
  });

  bench('issueResponse L=16', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    const [request] = issueRequest(paramsL16, ctx, rng);
    issueResponse(paramsL16, issuerKeysL16.privateKey, request, 100n, ctx, rng);
  });

  bench('issueResponse L=32', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    const [request] = issueRequest(paramsL32, ctx, rng);
    issueResponse(paramsL32, issuerKeysL32.privateKey, request, 100n, ctx, rng);
  });

  bench('issueResponse L=64', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    const [request] = issueRequest(paramsL64, ctx, rng);
    issueResponse(paramsL64, issuerKeysL64.privateKey, request, 100n, ctx, rng);
  });

  bench('issueResponse L=128', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    const [request] = issueRequest(paramsL128, ctx, rng);
    issueResponse(paramsL128, issuerKeysL128.privateKey, request, 100n, ctx, rng);
  });
});

describe('Token Creation (verifyIssuance)', () => {
  bench('verifyIssuance', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    const ctx = group.scalarFromBigint(0n);
    const [request, issueState] = issueRequest(paramsL8, ctx, rng);
    const response = issueResponse(paramsL8, issuerKeysL8.privateKey, request, 100n, ctx, rng);
    verifyIssuance(paramsL8, issuerKeysL8.publicKey, response, issueState);
  });
});

describe('Spend Proof Generation (by L)', () => {
  // Pre-create tokens for benchmarks
  const tokenL8 = createToken(paramsL8, issuerKeysL8, 100n, 0x100);
  const tokenL16 = createToken(paramsL16, issuerKeysL16, 100n, 0x101);
  const tokenL32 = createToken(paramsL32, issuerKeysL32, 100n, 0x102);
  const tokenL64 = createToken(paramsL64, issuerKeysL64, 100n, 0x103);
  const tokenL128 = createToken(paramsL128, issuerKeysL128, 100n, 0x104);

  bench('proveSpend L=8', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    proveSpend(paramsL8, tokenL8, 30n, rng);
  });

  bench('proveSpend L=16', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    proveSpend(paramsL16, tokenL16, 30n, rng);
  });

  bench('proveSpend L=32', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    proveSpend(paramsL32, tokenL32, 30n, rng);
  });

  bench('proveSpend L=64', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    proveSpend(paramsL64, tokenL64, 30n, rng);
  });

  bench('proveSpend L=128', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    proveSpend(paramsL128, tokenL128, 30n, rng);
  });
});

describe('Spend Proof Verification (by L)', () => {
  // Pre-create tokens and spend proofs
  const tokenL8 = createToken(paramsL8, issuerKeysL8, 100n, 0x200);
  const tokenL16 = createToken(paramsL16, issuerKeysL16, 100n, 0x201);
  const tokenL32 = createToken(paramsL32, issuerKeysL32, 100n, 0x202);
  const tokenL64 = createToken(paramsL64, issuerKeysL64, 100n, 0x203);
  const tokenL128 = createToken(paramsL128, issuerKeysL128, 100n, 0x204);

  const [proofL8] = createSpendProof(paramsL8, issuerKeysL8, tokenL8, 30n, 0x210);
  const [proofL16] = createSpendProof(paramsL16, issuerKeysL16, tokenL16, 30n, 0x211);
  const [proofL32] = createSpendProof(paramsL32, issuerKeysL32, tokenL32, 30n, 0x212);
  const [proofL64] = createSpendProof(paramsL64, issuerKeysL64, tokenL64, 30n, 0x213);
  const [proofL128] = createSpendProof(paramsL128, issuerKeysL128, tokenL128, 30n, 0x214);

  bench('verifySpendProof L=8', () => {
    verifySpendProof(paramsL8, issuerKeysL8.privateKey, proofL8);
  });

  bench('verifySpendProof L=16', () => {
    verifySpendProof(paramsL16, issuerKeysL16.privateKey, proofL16);
  });

  bench('verifySpendProof L=32', () => {
    verifySpendProof(paramsL32, issuerKeysL32.privateKey, proofL32);
  });

  bench('verifySpendProof L=64', () => {
    verifySpendProof(paramsL64, issuerKeysL64.privateKey, proofL64);
  });

  bench('verifySpendProof L=128', () => {
    verifySpendProof(paramsL128, issuerKeysL128.privateKey, proofL128);
  });
});

describe('Refund Issuance (by L)', () => {
  // Pre-create tokens and spend proofs
  const tokenL8 = createToken(paramsL8, issuerKeysL8, 100n, 0x300);
  const tokenL16 = createToken(paramsL16, issuerKeysL16, 100n, 0x301);
  const tokenL32 = createToken(paramsL32, issuerKeysL32, 100n, 0x302);
  const tokenL64 = createToken(paramsL64, issuerKeysL64, 100n, 0x303);
  const tokenL128 = createToken(paramsL128, issuerKeysL128, 100n, 0x304);

  const [proofL8] = createSpendProof(paramsL8, issuerKeysL8, tokenL8, 30n, 0x310);
  const [proofL16] = createSpendProof(paramsL16, issuerKeysL16, tokenL16, 30n, 0x311);
  const [proofL32] = createSpendProof(paramsL32, issuerKeysL32, tokenL32, 30n, 0x312);
  const [proofL64] = createSpendProof(paramsL64, issuerKeysL64, tokenL64, 30n, 0x313);
  const [proofL128] = createSpendProof(paramsL128, issuerKeysL128, tokenL128, 30n, 0x314);

  bench('issueRefund L=8', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    issueRefund(paramsL8, issuerKeysL8.privateKey, proofL8, 0n, rng);
  });

  bench('issueRefund L=16', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    issueRefund(paramsL16, issuerKeysL16.privateKey, proofL16, 0n, rng);
  });

  bench('issueRefund L=32', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    issueRefund(paramsL32, issuerKeysL32.privateKey, proofL32, 0n, rng);
  });

  bench('issueRefund L=64', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    issueRefund(paramsL64, issuerKeysL64.privateKey, proofL64, 0n, rng);
  });

  bench('issueRefund L=128', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    issueRefund(paramsL128, issuerKeysL128.privateKey, proofL128, 0n, rng);
  });
});

describe('Refund Token Creation (by L)', () => {
  // Pre-create full flow for each L
  const tokenL8 = createToken(paramsL8, issuerKeysL8, 100n, 0x400);
  const [proofL8, stateL8] = createSpendProof(paramsL8, issuerKeysL8, tokenL8, 30n, 0x410);
  const refundL8 = issueRefund(paramsL8, issuerKeysL8.privateKey, proofL8, 0n, createRng(0x420));

  const tokenL16 = createToken(paramsL16, issuerKeysL16, 100n, 0x401);
  const [proofL16, stateL16] = createSpendProof(paramsL16, issuerKeysL16, tokenL16, 30n, 0x411);
  const refundL16 = issueRefund(
    paramsL16,
    issuerKeysL16.privateKey,
    proofL16,
    0n,
    createRng(0x421)
  );

  const tokenL32 = createToken(paramsL32, issuerKeysL32, 100n, 0x402);
  const [proofL32, stateL32] = createSpendProof(paramsL32, issuerKeysL32, tokenL32, 30n, 0x412);
  const refundL32 = issueRefund(
    paramsL32,
    issuerKeysL32.privateKey,
    proofL32,
    0n,
    createRng(0x422)
  );

  const tokenL64 = createToken(paramsL64, issuerKeysL64, 100n, 0x403);
  const [proofL64, stateL64] = createSpendProof(paramsL64, issuerKeysL64, tokenL64, 30n, 0x413);
  const refundL64 = issueRefund(
    paramsL64,
    issuerKeysL64.privateKey,
    proofL64,
    0n,
    createRng(0x423)
  );

  const tokenL128 = createToken(paramsL128, issuerKeysL128, 100n, 0x404);
  const [proofL128, stateL128] = createSpendProof(
    paramsL128,
    issuerKeysL128,
    tokenL128,
    30n,
    0x414
  );
  const refundL128 = issueRefund(
    paramsL128,
    issuerKeysL128.privateKey,
    proofL128,
    0n,
    createRng(0x424)
  );

  bench('constructRefundToken L=8', () => {
    constructRefundToken(paramsL8, issuerKeysL8.publicKey, proofL8, refundL8, stateL8);
  });

  bench('constructRefundToken L=16', () => {
    constructRefundToken(paramsL16, issuerKeysL16.publicKey, proofL16, refundL16, stateL16);
  });

  bench('constructRefundToken L=32', () => {
    constructRefundToken(paramsL32, issuerKeysL32.publicKey, proofL32, refundL32, stateL32);
  });

  bench('constructRefundToken L=64', () => {
    constructRefundToken(paramsL64, issuerKeysL64.publicKey, proofL64, refundL64, stateL64);
  });

  bench('constructRefundToken L=128', () => {
    constructRefundToken(paramsL128, issuerKeysL128.publicKey, proofL128, refundL128, stateL128);
  });
});

describe('Full Protocol Flow', () => {
  bench('full issuance→spend→refund L=8', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    const ctx = group.scalarFromBigint(0n);

    // Issuance
    const [request, issueState] = issueRequest(paramsL8, ctx, rng);
    const response = issueResponse(paramsL8, issuerKeysL8.privateKey, request, 100n, ctx, rng);
    const token = verifyIssuance(paramsL8, issuerKeysL8.publicKey, response, issueState);

    // Spend
    const [spendProof, spendState] = proveSpend(paramsL8, token, 30n, rng);
    verifySpendProof(paramsL8, issuerKeysL8.privateKey, spendProof);

    // Refund
    const refund = issueRefund(paramsL8, issuerKeysL8.privateKey, spendProof, 0n, rng);
    constructRefundToken(paramsL8, issuerKeysL8.publicKey, spendProof, refund, spendState);
  });

  bench('full issuance→spend→refund L=64', () => {
    const rng = createRng(Math.random() * 0xffffffff);
    const ctx = group.scalarFromBigint(0n);

    // Issuance
    const [request, issueState] = issueRequest(paramsL64, ctx, rng);
    const response = issueResponse(paramsL64, issuerKeysL64.privateKey, request, 100n, ctx, rng);
    const token = verifyIssuance(paramsL64, issuerKeysL64.publicKey, response, issueState);

    // Spend
    const [spendProof, spendState] = proveSpend(paramsL64, token, 30n, rng);
    verifySpendProof(paramsL64, issuerKeysL64.privateKey, spendProof);

    // Refund
    const refund = issueRefund(paramsL64, issuerKeysL64.privateKey, spendProof, 0n, rng);
    constructRefundToken(paramsL64, issuerKeysL64.publicKey, spendProof, refund, spendState);
  });
});
