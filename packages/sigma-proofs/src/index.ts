/**
 * Sigma protocols for linear relations (draft-irtf-cfrg-sigma-protocols-03)
 * under the Fiat-Shamir transform (draft-irtf-cfrg-fiat-shamir-03).
 *
 * @module
 */

export {
  BLS12381,
  P256,
  SigmaError,
  deserializeElement,
  deserializeScalar,
  registerFixedBase,
  serializeElement,
  serializeScalar,
  type Ciphersuite,
  type Point,
} from './ciphersuites.js';
export { LinearRelation, type Equation, type ImageTerm, type Term } from './linear-relation.js';
export {
  decodeField,
  deriveSessionId,
  proveBatchable,
  proveBatchableAsync,
  proveBatchableEffect,
  proveCompact,
  proveCompactAsync,
  proveCompactEffect,
  randomNonces,
  spongeInit,
  verifyBatchable,
  verifyBatchableAsync,
  verifyBatchableEffect,
  verifyCompact,
  verifyCompactAsync,
  verifyCompactEffect,
} from './fiat-shamir.js';
export { type Effect, type Job, mulAll, runAsync, runSync } from './effects.js';
export { mulManyWebCrypto } from './webcrypto.js';
