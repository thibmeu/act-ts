/**
 * Anonymous Credit Tokens (ACT)
 *
 * Implementation of draft-schlesinger-cfrg-act-01
 * using draft-irtf-cfrg-sigma-protocols-01 and draft-irtf-cfrg-fiat-shamir-01.
 *
 * @module
 */

// Re-export sigma-proofs group for convenience
export { ristretto255 } from 'sigma-proofs';

// Core types
export type {
  Scalar,
  GroupElement,
  SystemParams,
  PrivateKey,
  PublicKey,
  KeyPair,
  CreditToken,
  IssuanceState,
  IssuanceRequest,
  IssuanceResponse,
  SpendState,
  SpendProof,
  Refund,
  PRNG,
} from './types.js';

export { ACTError, ACTErrorCode } from './types.js';

// System parameters
export {
  generateParameters,
  setGenerators,
  validateDomainSeparator,
  createDomainSeparator,
} from './params.js';

// Key generation
export {
  keyGen,
  derivePublicKey,
  privateKeyToBytes,
  privateKeyFromBytes,
  publicKeyToBytes,
  publicKeyFromBytes,
} from './keygen.js';

// Issuance protocol
export {
  issueRequest,
  issueResponse,
  verifyIssuance,
  serializeProof,
  deserializeProof,
} from './issuance.js';

// Spending protocol
export {
  proveSpend,
  verifySpendProof,
  issueRefund,
  constructRefundToken,
  verifyAndRefund,
  getSpendInstanceLabel,
} from './spend.js';

// TLS wire format encoding
export {
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
  encodeIssuanceState,
  decodeIssuanceState,
  encodeSpendState,
  decodeSpendState,
  encodePrivateKey,
  decodePrivateKey,
  encodePublicKey,
  decodePublicKey,
  EncodingError,
  EncodingErrorCode,
} from './encoding.js';

// RNG implementations
export { WebCryptoPRNG, SeededPRNGForTestingOnly, defaultPRNG, toHex } from './rng.js';

export const VERSION = '0.1.0';
