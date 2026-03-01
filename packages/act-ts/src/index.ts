/**
 * Anonymous Credit Tokens (ACT)
 *
 * Implementation of draft-schlesinger-cfrg-act-01
 * https://www.ietf.org/archive/id/draft-schlesinger-cfrg-act-01.txt
 *
 * @module
 */

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
} from './types.js';

export { ACTError, ACTErrorCode } from './types.js';

// Group operations
export { group, Ristretto255Scalar, Ristretto255Element } from './group.js';

// System parameters
export {
  generateParameters,
  validateDomainSeparator,
  createDomainSeparator,
} from './params.js';

// Key generation
export {
  keyGen,
  privateKeyToBytes,
  privateKeyFromBytes,
  publicKeyToBytes,
  publicKeyFromBytes,
  derivePublicKey,
} from './keygen.js';

// Issuance protocol
export {
  issueRequest,
  issueResponse,
  verifyIssuance,
  createIssuanceFlow,
  type IssuanceFlow,
} from './issuance.js';

// Spending protocol
export {
  proveSpend,
  verifySpendProof,
  issueRefund,
  constructRefundToken,
  verifyAndRefund,
} from './spend.js';

// Transcript (for advanced use)
export { Transcript, SimpleTranscript, PROTOCOL_VERSION } from './transcript.js';

// CBOR wire format (Section 4)
export {
  encodeIssuanceRequest,
  decodeIssuanceRequest,
  encodeIssuanceResponse,
  decodeIssuanceResponse,
  encodeCreditToken,
  decodeCreditToken,
  encodeSpendProof,
  decodeSpendProof,
  encodeRefund,
  decodeRefund,
  encodePreIssuance,
  decodePreIssuance,
  encodePreRefund,
  decodePreRefund,
  encodeKeyPair,
  decodeKeyPair,
  encodePublicKey,
  decodePublicKey,
  encodeError,
  decodeError,
} from './cbor.js';

export const VERSION = '0.0.1';
