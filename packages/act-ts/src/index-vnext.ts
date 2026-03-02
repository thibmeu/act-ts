/**
 * Anonymous Credit Tokens (ACT) - VNEXT
 *
 * Implementation of draft-schlesinger-cfrg-act (sigma-draft-compliance branch)
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
} from './types-vnext.js';

export { ACTError, ACTErrorCode } from './types-vnext.js';

// System parameters
export {
  generateParameters,
  setGenerators,
  validateDomainSeparator,
  createDomainSeparator,
} from './params-vnext.js';

// Key generation
export {
  keyGen,
  derivePublicKey,
  privateKeyToBytes,
  privateKeyFromBytes,
  publicKeyToBytes,
  publicKeyFromBytes,
} from './keygen-vnext.js';

// Issuance protocol
export {
  issueRequest,
  issueResponse,
  verifyIssuance,
  serializeProof,
  deserializeProof,
} from './issuance-vnext.js';

// Spending protocol
export {
  proveSpend,
  verifySpendProof,
  issueRefund,
  constructRefundToken,
  verifyAndRefund,
} from './spend-vnext.js';

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
} from './encoding-vnext.js';

// RNG implementations
export { WebCryptoPRNG, SeededPRNGForTestingOnly, defaultPRNG, toHex } from './rng.js';

export const VERSION = '0.1.0-vnext';
