/**
 * ACT Key Generation
 *
 * Section 3.2: Key Generation
 */

import type { Group } from 'sigma-proofs';
import type { PrivateKey, PublicKey, KeyPair } from './encoding.js';
import type { PRNG } from './rng.js';

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
