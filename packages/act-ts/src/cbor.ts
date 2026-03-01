/**
 * ACT CBOR Wire Format
 *
 * Section 4: Protocol Messages and Wire Format
 *
 * All protocol messages are encoded using deterministic CBOR (RFC 8949).
 */

import { encode, decode } from 'cbor2';
import { hexToBytes, bytesToHex } from '@noble/curves/utils.js';
import type {
  SystemParams,
  PrivateKey,
  PublicKey,
  IssuanceRequest,
  IssuanceResponse,
  CreditToken,
  SpendProof,
  SpendState,
  Refund,
  Scalar,
  GroupElement,
} from './types.js';
import { group } from './group.js';

/**
 * Section 4.1.1: Issuance Request Message
 *
 * IssuanceRequestMsg = {
 *     1: bstr,  ; K (compressed Ristretto point, 32 bytes)
 *     2: bstr,  ; gamma (scalar, 32 bytes)
 *     3: bstr,  ; k_bar (scalar, 32 bytes)
 *     4: bstr   ; r_bar (scalar, 32 bytes)
 * }
 */
export function encodeIssuanceRequest(req: IssuanceRequest): Uint8Array {
  const map = new Map<number, Uint8Array>([
    [1, req.K.toBytes()],
    [2, req.gamma.toBytes()],
    [3, req.kBar.toBytes()],
    [4, req.rBar.toBytes()],
  ]);
  return encode(map);
}

export function decodeIssuanceRequest(data: Uint8Array): IssuanceRequest {
  const map = decode(data) as Map<number, Uint8Array>;
  return {
    K: group.elementFromBytes(map.get(1)!),
    gamma: group.scalarFromBytes(map.get(2)!),
    kBar: group.scalarFromBytes(map.get(3)!),
    rBar: group.scalarFromBytes(map.get(4)!),
  };
}

/**
 * Section 4.1.2: Issuance Response Message
 *
 * IssuanceResponseMsg = {
 *     1: bstr,  ; A (compressed Ristretto point, 32 bytes)
 *     2: bstr,  ; e (scalar, 32 bytes)
 *     3: bstr,  ; gamma_resp (scalar, 32 bytes)
 *     4: bstr,  ; z (scalar, 32 bytes)
 *     5: bstr,  ; c (scalar, 32 bytes)
 *     6: bstr   ; ctx (scalar, 32 bytes)
 * }
 */
export function encodeIssuanceResponse(resp: IssuanceResponse): Uint8Array {
  const map = new Map<number, Uint8Array>([
    [1, resp.A.toBytes()],
    [2, resp.e.toBytes()],
    [3, resp.gammaResp.toBytes()],
    [4, resp.z.toBytes()],
    [5, group.scalarFromBigint(resp.c).toBytes()],
    [6, resp.ctx.toBytes()],
  ]);
  return encode(map);
}

export function decodeIssuanceResponse(data: Uint8Array): IssuanceResponse {
  const map = decode(data) as Map<number, Uint8Array>;
  const cScalar = group.scalarFromBytes(map.get(5)!);
  return {
    A: group.elementFromBytes(map.get(1)!),
    e: group.scalarFromBytes(map.get(2)!),
    gammaResp: group.scalarFromBytes(map.get(3)!),
    z: group.scalarFromBytes(map.get(4)!),
    c: (cScalar as { value: bigint }).value,
    ctx: group.scalarFromBytes(map.get(6)!),
  };
}

/**
 * Credit Token encoding (not in wire format, but useful for storage)
 *
 * CreditToken = {
 *     1: bstr,  ; A (compressed Ristretto point, 32 bytes)
 *     2: bstr,  ; e (scalar, 32 bytes)
 *     3: bstr,  ; k (scalar, 32 bytes) - nullifier
 *     4: bstr,  ; r (scalar, 32 bytes) - blinding
 *     5: bstr,  ; c (scalar, 32 bytes) - credits
 *     6: bstr   ; ctx (scalar, 32 bytes)
 * }
 */
export function encodeCreditToken(token: CreditToken): Uint8Array {
  const map = new Map<number, Uint8Array>([
    [1, token.A.toBytes()],
    [2, token.e.toBytes()],
    [3, token.k.toBytes()],
    [4, token.r.toBytes()],
    [5, group.scalarFromBigint(token.c).toBytes()],
    [6, token.ctx.toBytes()],
  ]);
  return encode(map);
}

export function decodeCreditToken(data: Uint8Array): CreditToken {
  const map = decode(data) as Map<number, Uint8Array>;
  const cScalar = group.scalarFromBytes(map.get(5)!);
  return {
    A: group.elementFromBytes(map.get(1)!),
    e: group.scalarFromBytes(map.get(2)!),
    k: group.scalarFromBytes(map.get(3)!),
    r: group.scalarFromBytes(map.get(4)!),
    c: (cScalar as { value: bigint }).value,
    ctx: group.scalarFromBytes(map.get(6)!),
  };
}

/**
 * Section 4.1.3: Spend Proof Message
 *
 * SpendProofMsg = {
 *     1: bstr,           ; k (nullifier, 32 bytes)
 *     2: bstr,           ; s (spend amount, 32 bytes)
 *     3: bstr,           ; A' (compressed point, 32 bytes)
 *     4: bstr,           ; B_bar (compressed point, 32 bytes)
 *     5: [* bstr],       ; Com array (L compressed points)
 *     6: bstr,           ; gamma (scalar, 32 bytes)
 *     7: bstr,           ; e_bar (scalar, 32 bytes)
 *     8: bstr,           ; r2_bar (scalar, 32 bytes)
 *     9: bstr,           ; r3_bar (scalar, 32 bytes)
 *     10: bstr,          ; c_bar (scalar, 32 bytes)
 *     11: bstr,          ; r_bar (scalar, 32 bytes)
 *     12: bstr,          ; w00 (scalar, 32 bytes)
 *     13: bstr,          ; w01 (scalar, 32 bytes)
 *     14: [* bstr],      ; gamma0 array (L scalars)
 *     15: [* [bstr, bstr]], ; z array (L pairs of scalars)
 *     16: bstr,          ; k_bar (scalar, 32 bytes)
 *     17: bstr,          ; s_bar (scalar, 32 bytes)
 *     18: bstr           ; ctx (scalar, 32 bytes)
 * }
 */
export function encodeSpendProof(proof: SpendProof): Uint8Array {
  const map = new Map<number, Uint8Array | Uint8Array[] | [Uint8Array, Uint8Array][]>([
    [1, proof.k.toBytes()],
    [2, group.scalarFromBigint(proof.s).toBytes()],
    [3, proof.APrime.toBytes()],
    [4, proof.BBar.toBytes()],
    [5, proof.Com.map(c => c.toBytes())],
    [6, proof.gamma.toBytes()],
    [7, proof.eBar.toBytes()],
    [8, proof.r2Bar.toBytes()],
    [9, proof.r3Bar.toBytes()],
    [10, proof.cBar.toBytes()],
    [11, proof.rBar.toBytes()],
    [12, proof.w00.toBytes()],
    [13, proof.w01.toBytes()],
    [14, proof.gamma0.map(g => g.toBytes())],
    [15, proof.z.map(([z0, z1]) => [z0.toBytes(), z1.toBytes()])],
    [16, proof.kBarFinal.toBytes()],
    [17, proof.sBarFinal.toBytes()],
    [18, proof.ctx.toBytes()],
  ]);
  return encode(map);
}

export function decodeSpendProof(data: Uint8Array): SpendProof {
  const map = decode(data) as Map<number, unknown>;
  const sScalar = group.scalarFromBytes(map.get(2) as Uint8Array);
  return {
    k: group.scalarFromBytes(map.get(1) as Uint8Array),
    s: (sScalar as { value: bigint }).value,
    APrime: group.elementFromBytes(map.get(3) as Uint8Array),
    BBar: group.elementFromBytes(map.get(4) as Uint8Array),
    Com: (map.get(5) as Uint8Array[]).map(b => group.elementFromBytes(b)),
    gamma: group.scalarFromBytes(map.get(6) as Uint8Array),
    eBar: group.scalarFromBytes(map.get(7) as Uint8Array),
    r2Bar: group.scalarFromBytes(map.get(8) as Uint8Array),
    r3Bar: group.scalarFromBytes(map.get(9) as Uint8Array),
    cBar: group.scalarFromBytes(map.get(10) as Uint8Array),
    rBar: group.scalarFromBytes(map.get(11) as Uint8Array),
    w00: group.scalarFromBytes(map.get(12) as Uint8Array),
    w01: group.scalarFromBytes(map.get(13) as Uint8Array),
    gamma0: (map.get(14) as Uint8Array[]).map(b => group.scalarFromBytes(b)),
    z: (map.get(15) as [Uint8Array, Uint8Array][]).map(
      ([z0, z1]) => [group.scalarFromBytes(z0), group.scalarFromBytes(z1)] as [Scalar, Scalar]
    ),
    kBarFinal: group.scalarFromBytes(map.get(16) as Uint8Array),
    sBarFinal: group.scalarFromBytes(map.get(17) as Uint8Array),
    ctx: group.scalarFromBytes(map.get(18) as Uint8Array),
  };
}

/**
 * Section 4.1.4: Refund Message
 *
 * RefundMsg = {
 *     1: bstr,  ; A* (compressed Ristretto point, 32 bytes)
 *     2: bstr,  ; e* (scalar, 32 bytes)
 *     3: bstr,  ; gamma (scalar, 32 bytes)
 *     4: bstr,  ; z (scalar, 32 bytes)
 *     5: bstr   ; t (partial return, scalar, 32 bytes)
 * }
 */
export function encodeRefund(refund: Refund): Uint8Array {
  const map = new Map<number, Uint8Array>([
    [1, refund.AStar.toBytes()],
    [2, refund.eStar.toBytes()],
    [3, refund.gamma.toBytes()],
    [4, refund.z.toBytes()],
    [5, group.scalarFromBigint(refund.t).toBytes()],
  ]);
  return encode(map);
}

export function decodeRefund(data: Uint8Array): Refund {
  const map = decode(data) as Map<number, Uint8Array>;
  const tScalar = group.scalarFromBytes(map.get(5)!);
  return {
    AStar: group.elementFromBytes(map.get(1)!),
    eStar: group.scalarFromBytes(map.get(2)!),
    gamma: group.scalarFromBytes(map.get(3)!),
    z: group.scalarFromBytes(map.get(4)!),
    t: (tScalar as { value: bigint }).value,
  };
}

/**
 * Pre-issuance state (client state before issuance)
 *
 * PreIssuance = {
 *     1: bstr,  ; r (blinding factor, 32 bytes)
 *     2: bstr   ; k (nullifier, 32 bytes)
 * }
 */
export function encodePreIssuance(state: { k: Scalar; r: Scalar }): Uint8Array {
  const map = new Map<number, Uint8Array>([
    [1, state.r.toBytes()],
    [2, state.k.toBytes()],
  ]);
  return encode(map);
}

export function decodePreIssuance(data: Uint8Array): { k: Scalar; r: Scalar } {
  const map = decode(data) as Map<number, Uint8Array>;
  return {
    r: group.scalarFromBytes(map.get(1)!),
    k: group.scalarFromBytes(map.get(2)!),
  };
}

/**
 * Pre-refund state (client state during spend)
 *
 * PreRefund = {
 *     1: bstr,  ; k* (new nullifier, 32 bytes)
 *     2: bstr,  ; r* (new blinding, 32 bytes)
 *     3: bstr,  ; m (remaining balance, 32 bytes)
 *     4: bstr   ; ctx (context, 32 bytes)
 * }
 */
export function encodePreRefund(state: SpendState): Uint8Array {
  const map = new Map<number, Uint8Array>([
    [1, state.kStar.toBytes()],
    [2, state.rStar.toBytes()],
    [3, group.scalarFromBigint(state.m).toBytes()],
    [4, state.ctx.toBytes()],
  ]);
  return encode(map);
}

export function decodePreRefund(data: Uint8Array): SpendState {
  const map = decode(data) as Map<number, Uint8Array>;
  const mScalar = group.scalarFromBytes(map.get(3)!);
  return {
    kStar: group.scalarFromBytes(map.get(1)!),
    rStar: group.scalarFromBytes(map.get(2)!),
    m: (mScalar as { value: bigint }).value,
    ctx: group.scalarFromBytes(map.get(4)!),
  };
}

/**
 * Key pair encoding
 *
 * KeyPair = {
 *     1: bstr,  ; sk (private key scalar, 32 bytes)
 *     2: bstr   ; pk (public key point, 32 bytes)
 * }
 */
export function encodeKeyPair(sk: PrivateKey, pk: PublicKey): Uint8Array {
  const map = new Map<number, Uint8Array>([
    [1, sk.x.toBytes()],
    [2, pk.W.toBytes()],
  ]);
  return encode(map);
}

export function decodeKeyPair(data: Uint8Array): { privateKey: PrivateKey; publicKey: PublicKey } {
  const map = decode(data) as Map<number, Uint8Array>;
  return {
    privateKey: { x: group.scalarFromBytes(map.get(1)!) },
    publicKey: { W: group.elementFromBytes(map.get(2)!) },
  };
}

/**
 * Public key encoding
 */
export function encodePublicKey(pk: PublicKey): Uint8Array {
  return encode(pk.W.toBytes());
}

export function decodePublicKey(data: Uint8Array): PublicKey {
  const bytes = decode(data) as Uint8Array;
  return { W: group.elementFromBytes(bytes) };
}

/**
 * Section 4.2: Error Responses
 *
 * ErrorMsg = {
 *     1: uint,   ; error_code
 *     2: tstr    ; error_message (for debugging only)
 * }
 */
export function encodeError(code: number, message: string): Uint8Array {
  const map = new Map<number, number | string>([
    [1, code],
    [2, message],
  ]);
  return encode(map);
}

export function decodeError(data: Uint8Array): { code: number; message: string } {
  const map = decode(data) as Map<number, number | string>;
  return {
    code: map.get(1) as number,
    message: map.get(2) as string,
  };
}
