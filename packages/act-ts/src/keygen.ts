/**
 * ACT Key Generation - VNEXT (sigma-draft-compliance)
 *
 * Section 3.2: Key Generation
 */

import type { Group } from 'sigma-proofs';
import type { PrivateKey, PublicKey, KeyPair, PRNG } from './types.js';

/**
 * Generate a new issuer key pair.
 *
 * KeyGen(G, rng):
 *   x <- Zq (random scalar)
 *   W = G * x
 *   return (PrivateKey(x), PublicKey(W))
 *
 * @param group - The elliptic curve group
 * @param rng - Random number generator
 * @returns Key pair
 */
export function keyGen(group: Group, rng: PRNG): KeyPair {
  // Generate random scalar using rng + hash-to-scalar for uniform distribution
  const bytes = rng.randomBytes(group.scalarSize + 16);
  const x = group.hashToScalar(bytes);

  const G = group.generator();
  const W = G.multiply(x);

  return {
    privateKey: { x },
    publicKey: { W },
  };
}

/**
 * Derive public key from private key.
 *
 * @param group - The elliptic curve group
 * @param sk - Private key
 * @returns Public key
 */
export function derivePublicKey(group: Group, sk: PrivateKey): PublicKey {
  const G = group.generator();
  const W = G.multiply(sk.x);
  return { W };
}

/**
 * Serialize private key to bytes.
 */
export function privateKeyToBytes(sk: PrivateKey): Uint8Array {
  return sk.x.toBytes();
}

/**
 * Deserialize private key from bytes.
 */
export function privateKeyFromBytes(group: Group, bytes: Uint8Array): PrivateKey {
  const x = group.scalarFromBytes(bytes);
  return { x };
}

/**
 * Serialize public key to bytes.
 */
export function publicKeyToBytes(pk: PublicKey): Uint8Array {
  return pk.W.toBytes();
}

/**
 * Deserialize public key from bytes.
 */
export function publicKeyFromBytes(group: Group, bytes: Uint8Array): PublicKey {
  const W = group.elementFromBytes(bytes);
  return { W };
}
