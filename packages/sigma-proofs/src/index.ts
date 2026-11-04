/**
 * Sigma protocols for linear relations (draft-irtf-cfrg-sigma-protocols-03)
 * under the Fiat-Shamir transform (draft-irtf-cfrg-fiat-shamir-03). Provers
 * and verifiers are asynchronous: their scalar multiplications run in batches
 * on WebCrypto where the ciphersuite allows it.
 *
 * @module
 */

export {
  BLS12381,
  type Ciphersuite,
  deserializeElement,
  deserializeScalar,
  P256,
  type Point,
  registerFixedBase,
  SigmaError,
  serializeElement,
  serializeScalar,
} from './ciphersuites.ts';
export {
  decodeField,
  deriveSessionId,
  proveBatchable,
  proveCompact,
  randomNonces,
  spongeInit,
  verifyBatchable,
  verifyCompact,
} from './fiat-shamir.ts';
export { type Equation, type ImageTerm, LinearRelation, type Term } from './linear-relation.ts';
export { type Job, mulMany } from './mul.ts';
