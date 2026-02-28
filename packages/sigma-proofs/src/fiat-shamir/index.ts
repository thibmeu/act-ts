/**
 * Fiat-Shamir transformation for sigma protocols.
 *
 * Implements draft-irtf-cfrg-fiat-shamir-01.
 *
 * @module
 */

export { Shake128Sponge, type DuplexSponge } from './sponge.js';
export { ByteCodec, type Codec } from './codec.js';
export {
  NISigmaProtocol,
  type NIOptions,
  type NIProof,
  type NIProofBatchable,
} from './ni-sigma.js';
