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
export type { Scalar, GroupElement } from 'sigma-proofs';

// Core types
export type { SystemParams } from './params.js';
export type { PRNG } from './rng.js';
export type { KeyPair } from './encoding.js';

// Errors
export { ACTError, ACTErrorCode } from './errors.js';

// System parameters
export {
  generateParameters,
  setGenerators,
  validateDomainSeparator,
  createDomainSeparator,
} from './params.js';

// Key generation
export { keyGen, derivePublicKey } from './keygen.js';

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

// Serialization namespaces (TLS wire format)
export {
  PrivateKey,
  PublicKey,
  IssuanceRequest,
  IssuanceResponse,
  SpendProof,
  Refund,
  CreditToken,
  IssuanceState,
  SpendState,
  EncodingError,
  EncodingErrorCode,
} from './encoding.js';

// RNG implementations
export { WebCryptoPRNG, SeededPRNGForTestingOnly, defaultPRNG, toHex } from './rng.js';

export const VERSION = '0.1.0';
