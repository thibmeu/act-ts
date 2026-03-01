/**
 * ACT Key Generation
 *
 * Section 3.2: Key Generation
 */

import type { KeyPair, PrivateKey, PublicKey } from './types.js';
import { group } from './group.js';

/**
 * KeyGen - Generate issuer key pair
 *
 * Section 3.2:
 *   1. x <- Zq (random scalar)
 *   2. W = G * x
 *   3. sk = x
 *   4. pk = W
 *   5. return (sk, pk)
 *
 * @returns Key pair containing private and public keys
 */
export function keyGen(): KeyPair {
  // Step 1: Sample random scalar
  const x = group.randomScalar();

  // Step 2: Compute public key W = G * x
  const W = group.generator().multiply(x);

  return {
    privateKey: { x },
    publicKey: { W },
  };
}

/**
 * Serialize private key to bytes
 */
export function privateKeyToBytes(sk: PrivateKey): Uint8Array {
  return sk.x.toBytes();
}

/**
 * Deserialize private key from bytes
 */
export function privateKeyFromBytes(bytes: Uint8Array): PrivateKey {
  const x = group.scalarFromBytes(bytes);
  return { x };
}

/**
 * Serialize public key to bytes
 */
export function publicKeyToBytes(pk: PublicKey): Uint8Array {
  return pk.W.toBytes();
}

/**
 * Deserialize public key from bytes
 */
export function publicKeyFromBytes(bytes: Uint8Array): PublicKey {
  const W = group.elementFromBytes(bytes);
  return { W };
}

/**
 * Derive public key from private key
 */
export function derivePublicKey(sk: PrivateKey): PublicKey {
  const W = group.generator().multiply(sk.x);
  return { W };
}
