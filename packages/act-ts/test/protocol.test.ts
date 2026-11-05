import { describe, expect, it, vi } from 'vitest';
import {
  ACTError,
  type Credential,
  createParams,
  decodeCredential,
  decodeIssuanceState,
  decodeIssueRequest,
  decodeIssueResponse,
  decodeRefund,
  decodeSpend,
  decodeSpendState,
  encodeCredential,
  encodeIssuanceState,
  encodeIssueRequest,
  encodeIssueResponse,
  encodeRefund,
  encodeSpend,
  encodeSpendState,
  finalizeIssue,
  finalizeRefund,
  generateKeys,
  issueRefund,
  issueRequest,
  issueResponse,
  type Params,
  proveSpend,
  rangeWeights,
  type SpendMessage,
  VerifiedSpend,
  verifySpend,
} from '../src/index.ts';

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const ctxCred = enc('epoch-42');
const ctxSpend = enc('challenge-digest');

const L = 8;
const params = createParams(L);
const { skM, pkM } = await generateKeys(params);

async function issue(c: bigint, p: Params = params): Promise<Credential> {
  const { state, request } = await issueRequest(p);
  return finalizeIssue(p, pkM, ctxCred, state, await issueResponse(p, skM, ctxCred, c, request));
}

const spend = async (c = 100n, s = 30n, a = 0n) =>
  proveSpend(params, await issue(c), ctxCred, s, a, ctxSpend);

/** The ACTError code `f` fails with, or undefined if it succeeds. */
async function code(f: () => unknown): Promise<string | undefined> {
  try {
    await f();
  } catch (e) {
    if (e instanceof ACTError) return e.code;
    throw e;
  }
  return undefined;
}

describe('flows', () => {
  it.each([
    ['ordinary spend', 100n, 30n, 0n, 5n, 75n],
    ['refresh', 100n, 0n, 0n, 0n, 100n],
    ['pure top-up', 100n, 0n, 50n, 50n, 150n],
    ['spend with top-up', 100n, 30n, 20n, 50n, 120n],
    ['spend everything', 255n, 255n, 0n, 0n, 0n],
    ['zero balance refresh', 0n, 0n, 0n, 0n, 0n],
    ['top up to the maximum', 0n, 0n, 255n, 255n, 255n],
  ])('%s', async (_, c, s, a, t, expected) => {
    const { state, proof } = await spend(c, s, a);
    // Every message and state survives its encoding.
    const wire = decodeSpend(params, encodeSpend(proof));
    expect(encodeSpend(wire)).toEqual(encodeSpend(proof));
    const stored = decodeSpendState(params, encodeSpendState(state));
    const verified = await verifySpend(params, skM, ctxCred, ctxSpend, wire);
    expect(verified.s).toBe(s);
    expect(verified.a).toBe(a);
    const refund = decodeRefund(params, encodeRefund(await issueRefund(verified, t)));
    const next = await finalizeRefund(params, pkM, ctxCred, stored, refund);
    expect(next.c).toBe(expected);
    expect(encodeCredential(decodeCredential(params, encodeCredential(next)))).toEqual(
      encodeCredential(next)
    );
    // The new Credential spends again.
    const again = await proveSpend(params, next, ctxCred, 0n, 0n, ctxSpend);
    await verifySpend(params, skM, ctxCred, ctxSpend, again.proof);
  });

  it('runs on noble where WebCrypto is unavailable', async () => {
    const real = globalThis.crypto;
    vi.stubGlobal('crypto', { getRandomValues: real.getRandomValues.bind(real) });
    try {
      const { state, proof } = await spend(100n, 30n, 10n);
      const verified = await verifySpend(params, skM, ctxCred, ctxSpend, proof);
      const next = await finalizeRefund(
        params,
        pkM,
        ctxCred,
        state,
        await issueRefund(verified, 35n)
      );
      expect(next.c).toBe(105n);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('issuance messages roundtrip', async () => {
    const { request } = await issueRequest(params);
    const req = decodeIssueRequest(encodeIssueRequest(request));
    const res = await issueResponse(params, skM, ctxCred, 7n, req);
    expect(encodeIssueResponse(decodeIssueResponse(params, encodeIssueResponse(res)))).toEqual(
      encodeIssueResponse(res)
    );
    expect(encodeIssueRequest(request)).toHaveLength(129);
    expect(encodeIssueResponse(res)).toHaveLength(137);
  });

  it('spend sizes follow Section 4.7', async () => {
    const size = async (s: bigint, a: bigint) =>
      encodeSpend((await spend(255n, s, a)).proof).length;
    expect(await size(0n, 0n)).toBe(468);
    expect(await size(1n, 0n)).toBe(129 * L + 403);
    expect(await size(200n, 0n)).toBe(129 * rangeWeights(params, 255n - 200n).length + 403);
  });
});

describe('verification binds every input', () => {
  it.each([
    ['spend', 1n],
    ['refresh', 0n],
  ])('%s authorizes only the snapshotted message', async (_, amount) => {
    const { state, proof } = await spend(10n, amount);
    const message = { ...proof, com1: [...proof.com1], pok: proof.pok.slice() };
    const challenge = ctxSpend.slice();
    const pending = verifySpend(params, skM, ctxCred, challenge, message);
    message.Kn = message.Kn.add(params.H1.multiply(100n));
    message.k = 0n;
    message.s = 200n;
    message.a = 1n;
    message.com1.length = 0;
    message.comC = params.H1;
    message.pok.fill(0);
    challenge.fill(0);
    const verified = await pending;
    expect(verified.s).toBe(amount);
    expect(verified.a).toBe(0n);
    const refund = await issueRefund(verified, 0n);
    const next = await finalizeRefund(params, pkM, ctxCred, state, refund);
    expect(next.c).toBe(10n - amount);
  });

  it('issuance signs only the request that passed verification', async () => {
    const { state, request } = await issueRequest(params);
    const message = { ...request, pok: request.pok.slice() };
    const pending = issueResponse(params, skM, ctxCred, 10n, message);
    message.K = params.H1;
    message.pok.fill(0);
    const credential = await finalizeIssue(params, pkM, ctxCred, state, await pending);
    const { proof } = await proveSpend(params, credential, ctxCred, 1n, 0n, ctxSpend);
    await expect(verifySpend(params, skM, ctxCred, ctxSpend, proof)).resolves.toBeDefined();
  });

  it('finalization returns the credential that was verified', async () => {
    const issuance = await issueRequest(params);
    const state = { ...issuance.state };
    const response = await issueResponse(params, skM, ctxCred, 10n, issuance.request);
    const message = { ...response, pok: response.pok.slice() };
    const pending = finalizeIssue(params, pkM, ctxCred, state, message);
    state.k = 0n;
    state.r = 0n;
    message.c = 200n;
    message.A = params.H1;
    message.e = 0n;
    message.pok.fill(0);
    const credential = await pending;
    expect(credential.c).toBe(10n);
    const spent = await proveSpend(params, credential, ctxCred, 1n, 0n, ctxSpend);
    const verified = await verifySpend(params, skM, ctxCred, ctxSpend, spent.proof);
    const refund = { ...(await issueRefund(verified, 0n)) };
    const next = finalizeRefund(params, pkM, ctxCred, spent.state, refund);
    refund.A = params.H1;
    refund.e = 0n;
    refund.t = 200n;
    refund.pok.fill(0);
    const again = await proveSpend(params, await next, ctxCred, 1n, 0n, ctxSpend);
    await expect(verifySpend(params, skM, ctxCred, ctxSpend, again.proof)).resolves.toBeDefined();
  });

  it('rejects another credential context', async () => {
    const { proof } = await spend();
    expect(await code(() => verifySpend(params, skM, enc('epoch-43'), ctxSpend, proof))).toBe(
      'Verify'
    );
  });

  it('rejects another spend context', async () => {
    const { proof } = await spend();
    expect(await code(() => verifySpend(params, skM, ctxCred, enc('other'), proof))).toBe('Verify');
  });

  it('rejects another key', async () => {
    const other = await generateKeys(params);
    const { proof } = await spend();
    expect(await code(() => verifySpend(params, other.skM, ctxCred, ctxSpend, proof))).toBe(
      'Verify'
    );
  });

  it('rejects changed amounts', async () => {
    const { proof } = await spend();
    // Same shape (n = L either way), different statement.
    for (const changed of [
      { ...proof, s: 31n },
      { ...proof, a: 1n },
    ]) {
      expect(await code(() => verifySpend(params, skM, ctxCred, ctxSpend, changed))).toBe('Verify');
    }
  });

  it('rejects a tampered proof', async () => {
    const bytes = encodeSpend((await spend()).proof);
    bytes.set([(bytes.at(-1) ?? 0) ^ 1], bytes.length - 1);
    const tampered = decodeSpend(params, bytes);
    expect(await code(() => verifySpend(params, skM, ctxCred, ctxSpend, tampered))).toBe('Verify');
  });

  it('rejects a wrong shape', async () => {
    const { proof } = await spend();
    const C = proof.com1[0];
    expect(C).toBeDefined();
    const shapes: SpendMessage[] = [
      { ...proof, com1: proof.com1.slice(1) },
      { ...proof, comC: C },
      { ...proof, s: 0n, com1: [], comC: C },
    ];
    for (const p of shapes) {
      expect(await code(() => verifySpend(params, skM, ctxCred, ctxSpend, p))).toBe('Verify');
    }
  });

  it('rejects an identity A_prime (soundness-critical, Section 6)', async () => {
    const { proof } = await spend();
    const Aprime = proof.Aprime.subtract(proof.Aprime);
    expect(
      await code(() => verifySpend(params, skM, ctxCred, ctxSpend, { ...proof, Aprime }))
    ).toBe('Verify');
  });

  it('rejects a refund for another spend', async () => {
    const a = await spend();
    const b = await spend();
    const refund = await issueRefund(
      await verifySpend(params, skM, ctxCred, ctxSpend, b.proof),
      0n
    );
    expect(await code(() => finalizeRefund(params, pkM, ctxCred, a.state, refund))).toBe('Verify');
    // The state was not consumed by the failure.
    const own = await issueRefund(await verifySpend(params, skM, ctxCred, ctxSpend, a.proof), 0n);
    expect((await finalizeRefund(params, pkM, ctxCred, a.state, own)).c).toBe(70n);
  });

  it('rejects a response under another key', async () => {
    const other = await generateKeys(params);
    const { state, request } = await issueRequest(params);
    const response = await issueResponse(params, other.skM, ctxCred, 1n, request);
    expect(await code(() => finalizeIssue(params, pkM, ctxCred, state, response))).toBe('Verify');
  });

  it('rejects a tampered issuance request', async () => {
    const bytes = encodeIssueRequest((await issueRequest(params)).request);
    bytes.set([(bytes[40] ?? 0) ^ 1], 40);
    const tampered = decodeIssueRequest(bytes);
    expect(await code(() => issueResponse(params, skM, ctxCred, 1n, tampered))).toBe('Verify');
  });
});

describe('amounts (Section 4.3)', () => {
  it('rejects out-of-range amounts', async () => {
    const { request } = await issueRequest(params);
    expect(await code(() => issueResponse(params, skM, ctxCred, 256n, request))).toBe('Amount');
    const cred = await issue(100n);
    for (const [s, a] of [
      [101n, 0n],
      [0n, 156n],
      [-1n, 0n],
    ] as const) {
      expect(await code(() => proveSpend(params, cred, ctxCred, s, a, ctxSpend))).toBe('Amount');
    }
    // The failures did not consume the Credential.
    const { proof } = await proveSpend(params, cred, ctxCred, 10n, 20n, ctxSpend);
    const verified = await verifySpend(params, skM, ctxCred, ctxSpend, proof);
    expect(await code(() => issueRefund(verified, 31n))).toBe('Amount');
  });

  it('rejects s + a >= 2^L before computing the shape', async () => {
    const bytes = encodeSpend((await spend()).proof);
    bytes.set([0, 0, 0, 0, 0, 0, 0, 200], 40); // a = 200, s + a = 230 < 256 but shape differs
    expect(await code(() => decodeSpend(params, bytes))).toBe('Deserialize');
    bytes.set([0, 0, 0, 0, 0, 0, 0, 230], 40); // s + a = 260
    expect(await code(() => decodeSpend(params, bytes))).toBe('Amount');
    bytes.set([1, 0, 0, 0, 0, 0, 0, 0], 32); // s >= 2^L
    expect(await code(() => decodeSpend(params, bytes))).toBe('Amount');
  });

  it('computes range weights as in the draft', () => {
    expect(rangeWeights(params, 0n)).toEqual([]);
    expect(rangeWeights(params, 255n)).toEqual([1n, 2n, 4n, 8n, 16n, 32n, 64n, 128n]);
    expect(rangeWeights(params, 5n)).toEqual([1n, 2n, 2n]);
    expect(rangeWeights(createParams(64), (1n << 64n) - 1n)).toHaveLength(64);
  });

  it('handles L = 64 without overflow', async () => {
    const wide = createParams(64);
    const max = (1n << 64n) - 1n;
    const { proof } = await proveSpend(wide, await issue(max, wide), ctxCred, max, 0n, ctxSpend);
    await verifySpend(wide, skM, ctxCred, ctxSpend, proof);
    expect(await code(() => createParams(65))).toBe('Value');
    expect(await code(() => createParams(0))).toBe('Value');
  });
});

describe('single use (Section 6)', () => {
  it('consumes the Credential, the states, and the verified spend', async () => {
    const cred = await issue(10n);
    const { state, proof } = await proveSpend(params, cred, ctxCred, 1n, 0n, ctxSpend);
    expect(await code(() => proveSpend(params, cred, ctxCred, 1n, 0n, ctxSpend))).toBe('Value');
    const verified = await verifySpend(params, skM, ctxCred, ctxSpend, proof);
    const refund = await issueRefund(verified, 1n);
    expect(await code(() => issueRefund(verified, 1n))).toBe('Value');
    await finalizeRefund(params, pkM, ctxCred, state, refund);
    expect(await code(() => finalizeRefund(params, pkM, ctxCred, state, refund))).toBe('Value');

    const issuance = await issueRequest(params);
    const response = await issueResponse(params, skM, ctxCred, 1n, issuance.request);
    await finalizeIssue(params, pkM, ctxCred, issuance.state, response);
    expect(await code(() => finalizeIssue(params, pkM, ctxCred, issuance.state, response))).toBe(
      'Value'
    );
  });

  it('consumes copied and serialized credential and state values', async () => {
    const issuance = await issueRequest(params);
    const storedIssue = encodeIssuanceState(issuance.state);
    const response = await issueResponse(params, skM, ctxCred, 10n, issuance.request);
    const credential = await finalizeIssue(params, pkM, ctxCred, issuance.state, response);
    for (const copy of [{ ...issuance.state }, decodeIssuanceState(storedIssue)]) {
      await expect(finalizeIssue(params, pkM, ctxCred, copy, response)).rejects.toMatchObject({
        code: 'Value',
      });
    }
    const storedCredential = encodeCredential(credential);
    const { state, proof } = await proveSpend(params, credential, ctxCred, 1n, 0n, ctxSpend);
    for (const copy of [{ ...credential }, decodeCredential(params, storedCredential)]) {
      await expect(proveSpend(params, copy, ctxCred, 1n, 0n, ctxSpend)).rejects.toMatchObject({
        code: 'Value',
      });
    }
    const storedSpend = encodeSpendState(state);
    const refund = await issueRefund(await verifySpend(params, skM, ctxCred, ctxSpend, proof), 0n);
    await finalizeRefund(params, pkM, ctxCred, state, refund);
    for (const copy of [{ ...state }, decodeSpendState(params, storedSpend)]) {
      await expect(finalizeRefund(params, pkM, ctxCred, copy, refund)).rejects.toMatchObject({
        code: 'Value',
      });
    }
  });

  it('refuses concurrent uses of one Credential', async () => {
    const cred = await issue(10n);
    const results = await Promise.allSettled([
      proveSpend(params, cred, ctxCred, 1n, 0n, ctxSpend),
      proveSpend(params, { ...cred }, ctxCred, 1n, 0n, ctxSpend),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual(['fulfilled', 'rejected']);
  });

  it('only verifySpend creates a VerifiedSpend', async () => {
    const { proof } = await spend(10n, 1n);
    // The token is module-private; a look-alike symbol is refused.
    const forge = (): unknown =>
      Reflect.construct(VerifiedSpend, [Symbol('VerifiedSpend'), params, skM, 0n, proof.Kn, proof]);
    expect(forge).toThrow(ACTError);
  });
});

describe('timing (Section 6, "Constant time")', () => {
  it('does work independent of the hidden balance', async () => {
    // Remainders 0 (all bits zero) and 254 (seven bits set) must cost the same
    // number of WebCrypto key imports, or timing reveals the balance.
    const imports = async (c: bigint): Promise<number> => {
      const credential = await issue(c);
      const spy = vi.spyOn(globalThis.crypto.subtle, 'importKey');
      await proveSpend(params, credential, ctxCred, 1n, 0n, ctxSpend);
      const n = spy.mock.calls.filter(([format]) => format === 'pkcs8').length;
      spy.mockRestore();
      return n;
    };
    const zero = await imports(1n);
    expect(zero).toBeGreaterThan(0);
    expect(await imports(255n)).toBe(zero);
  });
});

describe('decoding (Section 4.7)', async () => {
  const bytes = encodeSpend((await spend(100n, 0n)).proof);

  it('rejects truncation and trailing bytes', async () => {
    expect(await code(() => decodeSpend(params, bytes.subarray(0, -1)))).toBe('Deserialize');
    expect(await code(() => decodeSpend(params, new Uint8Array([...bytes, 0])))).toBe(
      'Deserialize'
    );
  });

  it('rejects non-canonical scalars and invalid elements', async () => {
    const k = bytes.slice();
    k.fill(0xff, 0, 32); // nullifier >= p
    expect(await code(() => decodeSpend(params, k))).toBe('Deserialize');
    const pok = bytes.slice();
    pok.fill(0xff, pok.length - 32); // last response >= p
    expect(await code(() => decodeSpend(params, pok))).toBe('Deserialize');
    const point = bytes.slice();
    point[48] = 0x04; // not a compressed prefix
    expect(await code(() => decodeSpend(params, point))).toBe('Deserialize');
    point[48] = 0x00; // identity encoding
    expect(await code(() => decodeSpend(params, point))).toBe('Deserialize');
  });
});
