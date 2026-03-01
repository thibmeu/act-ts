/**
 * TLS Wire Format Encoding Tests (VNEXT)
 */

import { describe, it, expect } from 'vitest';
import { ristretto255 } from 'sigma-proofs';
import {
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
} from '../src/encoding-vnext.js';
import type {
  IssuanceRequest,
  IssuanceResponse,
  SpendProof,
  Refund,
  CreditToken,
  IssuanceState,
  SpendState,
  PrivateKey,
  PublicKey,
  Scalar,
} from '../src/types-vnext.js';

const group = ristretto255;

// Helper to create random bytes
function randomBytes(n: number): Uint8Array {
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  return bytes;
}

describe('TLS Wire Format Encoding (VNEXT)', () => {
  describe('IssuanceRequest', () => {
    it('roundtrips correctly', () => {
      const req: IssuanceRequest = {
        K: group.generator().multiply(group.randomScalar()),
        pok: randomBytes(64),
      };
      const encoded = encodeIssuanceRequest(req);
      const decoded = decodeIssuanceRequest(group, encoded);

      expect(decoded.K.equals(req.K)).toBe(true);
      expect(decoded.pok).toEqual(req.pok);
    });

    it('has expected size (34 + pok.length)', () => {
      const req: IssuanceRequest = {
        K: group.generator().multiply(group.randomScalar()),
        pok: randomBytes(96),
      };
      const encoded = encodeIssuanceRequest(req);
      // K[32] + len[2] + pok[96] = 130
      expect(encoded.length).toBe(32 + 2 + 96);
    });

    it('rejects truncated data', () => {
      const req: IssuanceRequest = {
        K: group.generator().multiply(group.randomScalar()),
        pok: randomBytes(64),
      };
      const encoded = encodeIssuanceRequest(req);
      expect(() => decodeIssuanceRequest(group, encoded.slice(0, 31))).toThrow(
        EncodingError
      );
    });

    it('rejects trailing data', () => {
      const req: IssuanceRequest = {
        K: group.generator().multiply(group.randomScalar()),
        pok: randomBytes(64),
      };
      const encoded = encodeIssuanceRequest(req);
      const withTrailing = new Uint8Array(encoded.length + 1);
      withTrailing.set(encoded);
      withTrailing[encoded.length] = 0xff;
      expect(() => decodeIssuanceRequest(group, withTrailing)).toThrow(EncodingError);
    });
  });

  describe('IssuanceResponse', () => {
    it('roundtrips correctly', () => {
      const resp: IssuanceResponse & { ctx: Scalar } = {
        A: group.generator().multiply(group.randomScalar()),
        e: group.randomScalar(),
        c: 100n,
        ctx: group.randomScalar(),
        pok: randomBytes(64),
      };
      const encoded = encodeIssuanceResponse(group, resp);
      const decoded = decodeIssuanceResponse(group, encoded);

      expect(decoded.A.equals(resp.A)).toBe(true);
      expect(decoded.e.equals(resp.e)).toBe(true);
      expect(decoded.c).toBe(resp.c);
      expect(decoded.ctx.equals(resp.ctx)).toBe(true);
      expect(decoded.pok).toEqual(resp.pok);
    });

    it('has expected size (130 + pok.length)', () => {
      const resp: IssuanceResponse & { ctx: Scalar } = {
        A: group.generator().multiply(group.randomScalar()),
        e: group.randomScalar(),
        c: 100n,
        ctx: group.randomScalar(),
        pok: randomBytes(128),
      };
      const encoded = encodeIssuanceResponse(group, resp);
      // A[32] + e[32] + c[32] + ctx[32] + len[2] + pok[128] = 258
      expect(encoded.length).toBe(32 * 4 + 2 + 128);
    });
  });

  describe('SpendProof', () => {
    it('roundtrips correctly for L=4', () => {
      const L = 4;
      const proof: SpendProof = {
        k: group.randomScalar(),
        s: 5n,
        ctx: group.randomScalar(),
        APrime: group.generator().multiply(group.randomScalar()),
        BBar: group.generator().multiply(group.randomScalar()),
        Com: Array.from({ length: L }, () =>
          group.generator().multiply(group.randomScalar())
        ),
        pok: randomBytes(256),
      };
      const encoded = encodeSpendProof(group, proof);
      const decoded = decodeSpendProof(group, L, encoded);

      expect(decoded.k.equals(proof.k)).toBe(true);
      expect(decoded.s).toBe(proof.s);
      expect(decoded.ctx.equals(proof.ctx)).toBe(true);
      expect(decoded.APrime.equals(proof.APrime)).toBe(true);
      expect(decoded.BBar.equals(proof.BBar)).toBe(true);
      expect(decoded.Com.length).toBe(L);
      for (let i = 0; i < L; i++) {
        expect(decoded.Com[i]!.equals(proof.Com[i]!)).toBe(true);
      }
      expect(decoded.pok).toEqual(proof.pok);
    });

    it('has expected size for L=8', () => {
      const L = 8;
      const proof: SpendProof = {
        k: group.randomScalar(),
        s: 100n,
        ctx: group.randomScalar(),
        APrime: group.generator().multiply(group.randomScalar()),
        BBar: group.generator().multiply(group.randomScalar()),
        Com: Array.from({ length: L }, () =>
          group.generator().multiply(group.randomScalar())
        ),
        pok: randomBytes(512),
      };
      const encoded = encodeSpendProof(group, proof);
      // k[32] + s[32] + ctx[32] + A'[32] + B_bar[32] + Com[8*32] + len[2] + pok[512]
      expect(encoded.length).toBe(32 * 5 + 32 * L + 2 + 512);
    });

    it('rejects invalid L', () => {
      const proof: SpendProof = {
        k: group.randomScalar(),
        s: 5n,
        ctx: group.randomScalar(),
        APrime: group.generator().multiply(group.randomScalar()),
        BBar: group.generator().multiply(group.randomScalar()),
        Com: [group.generator().multiply(group.randomScalar())],
        pok: randomBytes(64),
      };
      const encoded = encodeSpendProof(group, proof);
      expect(() => decodeSpendProof(group, 0, encoded)).toThrow(EncodingError);
      expect(() => decodeSpendProof(group, 129, encoded)).toThrow(EncodingError);
    });
  });

  describe('Refund', () => {
    it('roundtrips correctly', () => {
      const refund: Refund = {
        AStar: group.generator().multiply(group.randomScalar()),
        eStar: group.randomScalar(),
        t: 10n,
        pok: randomBytes(64),
      };
      const encoded = encodeRefund(group, refund);
      const decoded = decodeRefund(group, encoded);

      expect(decoded.AStar.equals(refund.AStar)).toBe(true);
      expect(decoded.eStar.equals(refund.eStar)).toBe(true);
      expect(decoded.t).toBe(refund.t);
      expect(decoded.pok).toEqual(refund.pok);
    });

    it('has expected size (98 + pok.length)', () => {
      const refund: Refund = {
        AStar: group.generator().multiply(group.randomScalar()),
        eStar: group.randomScalar(),
        t: 10n,
        pok: randomBytes(128),
      };
      const encoded = encodeRefund(group, refund);
      // A*[32] + e*[32] + t[32] + len[2] + pok[128] = 226
      expect(encoded.length).toBe(32 * 3 + 2 + 128);
    });
  });

  describe('CreditToken', () => {
    it('roundtrips correctly', () => {
      const token: CreditToken = {
        A: group.generator().multiply(group.randomScalar()),
        e: group.randomScalar(),
        k: group.randomScalar(),
        r: group.randomScalar(),
        c: 50n,
        ctx: group.randomScalar(),
      };
      const encoded = encodeCreditToken(group, token);
      const decoded = decodeCreditToken(group, encoded);

      expect(decoded.A.equals(token.A)).toBe(true);
      expect(decoded.e.equals(token.e)).toBe(true);
      expect(decoded.k.equals(token.k)).toBe(true);
      expect(decoded.r.equals(token.r)).toBe(true);
      expect(decoded.c).toBe(token.c);
      expect(decoded.ctx.equals(token.ctx)).toBe(true);
    });

    it('has fixed size of 192 bytes', () => {
      const token: CreditToken = {
        A: group.generator().multiply(group.randomScalar()),
        e: group.randomScalar(),
        k: group.randomScalar(),
        r: group.randomScalar(),
        c: 12345678901234567890n,
        ctx: group.randomScalar(),
      };
      const encoded = encodeCreditToken(group, token);
      expect(encoded.length).toBe(192);
    });
  });

  describe('IssuanceState', () => {
    it('roundtrips correctly', () => {
      const state: IssuanceState = {
        r: group.randomScalar(),
        k: group.randomScalar(),
        ctx: group.randomScalar(),
      };
      const encoded = encodeIssuanceState(state);
      const decoded = decodeIssuanceState(group, encoded);

      expect(decoded.r.equals(state.r)).toBe(true);
      expect(decoded.k.equals(state.k)).toBe(true);
      expect(decoded.ctx.equals(state.ctx)).toBe(true);
    });

    it('has fixed size of 96 bytes', () => {
      const state: IssuanceState = {
        r: group.randomScalar(),
        k: group.randomScalar(),
        ctx: group.randomScalar(),
      };
      const encoded = encodeIssuanceState(state);
      expect(encoded.length).toBe(96);
    });
  });

  describe('SpendState', () => {
    it('roundtrips correctly', () => {
      const state: SpendState = {
        rStar: group.randomScalar(),
        kStar: group.randomScalar(),
        m: 70n,
        ctx: group.randomScalar(),
      };
      const encoded = encodeSpendState(group, state);
      const decoded = decodeSpendState(group, encoded);

      expect(decoded.rStar.equals(state.rStar)).toBe(true);
      expect(decoded.kStar.equals(state.kStar)).toBe(true);
      expect(decoded.m).toBe(state.m);
      expect(decoded.ctx.equals(state.ctx)).toBe(true);
    });

    it('has fixed size of 128 bytes', () => {
      const state: SpendState = {
        rStar: group.randomScalar(),
        kStar: group.randomScalar(),
        m: 999n,
        ctx: group.randomScalar(),
      };
      const encoded = encodeSpendState(group, state);
      expect(encoded.length).toBe(128);
    });
  });

  describe('PrivateKey', () => {
    it('roundtrips correctly', () => {
      const sk: PrivateKey = { x: group.randomScalar() };
      const encoded = encodePrivateKey(sk);
      const decoded = decodePrivateKey(group, encoded);

      expect(decoded.x.equals(sk.x)).toBe(true);
    });

    it('has fixed size of 32 bytes', () => {
      const sk: PrivateKey = { x: group.randomScalar() };
      const encoded = encodePrivateKey(sk);
      expect(encoded.length).toBe(32);
    });
  });

  describe('PublicKey', () => {
    it('roundtrips correctly', () => {
      const pk: PublicKey = { W: group.generator().multiply(group.randomScalar()) };
      const encoded = encodePublicKey(pk);
      const decoded = decodePublicKey(group, encoded);

      expect(decoded.W.equals(pk.W)).toBe(true);
    });

    it('has fixed size of 32 bytes', () => {
      const pk: PublicKey = { W: group.generator().multiply(group.randomScalar()) };
      const encoded = encodePublicKey(pk);
      expect(encoded.length).toBe(32);
    });

    it('rejects identity point', () => {
      const identityBytes = group.identity().toBytes();
      expect(() => decodePublicKey(group, identityBytes)).toThrow(EncodingError);
    });
  });

  describe('Error handling', () => {
    it('throws EncodingError with correct codes', () => {
      // TooShort
      try {
        decodePublicKey(group, new Uint8Array(16));
      } catch (e) {
        expect(e).toBeInstanceOf(EncodingError);
        expect((e as EncodingError).code).toBe(EncodingErrorCode.TooShort);
      }

      // TrailingData
      const pk: PublicKey = { W: group.generator().multiply(group.randomScalar()) };
      const encoded = encodePublicKey(pk);
      const withTrailing = new Uint8Array(encoded.length + 5);
      withTrailing.set(encoded);
      try {
        decodePublicKey(group, withTrailing);
      } catch (e) {
        expect(e).toBeInstanceOf(EncodingError);
        expect((e as EncodingError).code).toBe(EncodingErrorCode.TrailingData);
      }

      // InvalidL
      try {
        decodeSpendProof(group, 200, new Uint8Array(1000));
      } catch (e) {
        expect(e).toBeInstanceOf(EncodingError);
        expect((e as EncodingError).code).toBe(EncodingErrorCode.InvalidL);
      }
    });
  });

  describe('Large values', () => {
    it('handles large credit amounts', () => {
      const largeCredit = (1n << 126n) - 1n;
      const token: CreditToken = {
        A: group.generator().multiply(group.randomScalar()),
        e: group.randomScalar(),
        k: group.randomScalar(),
        r: group.randomScalar(),
        c: largeCredit,
        ctx: group.randomScalar(),
      };
      const encoded = encodeCreditToken(group, token);
      const decoded = decodeCreditToken(group, encoded);

      expect(decoded.c).toBe(largeCredit);
    });

    it('handles large pok field', () => {
      const largePok = randomBytes(10000);
      const req: IssuanceRequest = {
        K: group.generator().multiply(group.randomScalar()),
        pok: largePok,
      };
      const encoded = encodeIssuanceRequest(req);
      const decoded = decodeIssuanceRequest(group, encoded);

      expect(decoded.pok).toEqual(largePok);
    });
  });
});
