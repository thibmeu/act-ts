import { describe, expect, it, vi } from 'vitest';
import {
  ACTError,
  type Credential,
  type Params,
  type SpendMessage,
  VerifiedSpend,
  createParams,
  decodeCredential,
  decodeIssueRequest,
  decodeIssueResponse,
  decodeRefund,
  decodeSpend,
  decodeSpendState,
  encodeCredential,
  encodeIssueRequest,
  encodeIssueResponse,
  encodeRefund,
  encodeSpend,
  encodeSpendState,
  finalizeIssue,
  finalizeIssueAsync,
  finalizeRefund,
  finalizeRefundAsync,
  generateKeys,
  issueRefund,
  issueRefundAsync,
  issueRequest,
  issueRequestAsync,
  issueResponse,
  issueResponseAsync,
  proveSpend,
  proveSpendAsync,
  rangeWeights,
  verifySpend,
  verifySpendAsync,
} from '../src/index.js';

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const ctxCred = enc('epoch-42');
const ctxSpend = enc('challenge-digest');

const L = 8;
const params = createParams(L);
const { skM, pkM } = generateKeys(params);

function issue(c: bigint, p: Params = params): Credential {
  const { state, request } = issueRequest(p);
  return finalizeIssue(p, pkM, ctxCred, state, issueResponse(p, skM, ctxCred, c, request));
}

function code(f: () => unknown): string | undefined {
  try {
    f();
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
  ])('%s', (_, c, s, a, t, expected) => {
    const { state, proof } = proveSpend(params, issue(c), ctxCred, s, a, ctxSpend);
    // Every message and state survives its encoding.
    const wire = decodeSpend(params, encodeSpend(proof));
    expect(encodeSpend(wire)).toEqual(encodeSpend(proof));
    const stored = decodeSpendState(params, encodeSpendState(state));
    const verified = verifySpend(params, skM, ctxCred, ctxSpend, wire);
    expect(verified.s).toBe(s);
    expect(verified.a).toBe(a);
    const refund = decodeRefund(params, encodeRefund(issueRefund(verified, t)));
    const next = finalizeRefund(params, pkM, ctxCred, stored, refund);
    expect(next.c).toBe(expected);
    expect(encodeCredential(decodeCredential(params, encodeCredential(next)))).toEqual(
      encodeCredential(next)
    );
    // The new Credential spends again.
    const again = proveSpend(params, next, ctxCred, 0n, 0n, ctxSpend);
    verifySpend(params, skM, ctxCred, ctxSpend, again.proof);
  });

  it('issuance messages roundtrip', () => {
    const { request } = issueRequest(params);
    const req = decodeIssueRequest(encodeIssueRequest(request));
    const res = issueResponse(params, skM, ctxCred, 7n, req);
    expect(encodeIssueResponse(decodeIssueResponse(params, encodeIssueResponse(res)))).toEqual(
      encodeIssueResponse(res)
    );
    expect(encodeIssueRequest(request)).toHaveLength(129);
    expect(encodeIssueResponse(res)).toHaveLength(137);
  });

  it('spend sizes follow Section 4.7', () => {
    const size = (s: bigint, a: bigint): number =>
      encodeSpend(proveSpend(params, issue(255n), ctxCred, s, a, ctxSpend).proof).length;
    expect(size(0n, 0n)).toBe(468);
    expect(size(1n, 0n)).toBe(129 * L + 403);
    expect(size(200n, 0n)).toBe(129 * rangeWeights(params, 255n - 200n).length + 403);
  });
});

describe('verification binds every input', () => {
  const spend = () => proveSpend(params, issue(100n), ctxCred, 30n, 0n, ctxSpend);

  it('rejects another credential context', () => {
    expect(code(() => verifySpend(params, skM, enc('epoch-43'), ctxSpend, spend().proof))).toBe(
      'Verify'
    );
  });

  it('rejects another spend context', () => {
    expect(code(() => verifySpend(params, skM, ctxCred, enc('other'), spend().proof))).toBe(
      'Verify'
    );
  });

  it('rejects another key', () => {
    const other = generateKeys(params);
    expect(code(() => verifySpend(params, other.skM, ctxCred, ctxSpend, spend().proof))).toBe(
      'Verify'
    );
  });

  it('rejects changed amounts', () => {
    const { proof } = spend();
    // Same shape (n = L either way), different statement.
    expect(code(() => verifySpend(params, skM, ctxCred, ctxSpend, { ...proof, s: 31n }))).toBe(
      'Verify'
    );
    expect(code(() => verifySpend(params, skM, ctxCred, ctxSpend, { ...proof, a: 1n }))).toBe(
      'Verify'
    );
  });

  it('rejects a tampered proof', () => {
    const bytes = encodeSpend(spend().proof);
    bytes.set([(bytes.at(-1) ?? 0) ^ 1], bytes.length - 1);
    expect(
      code(() => verifySpend(params, skM, ctxCred, ctxSpend, decodeSpend(params, bytes)))
    ).toBe('Verify');
  });

  it('rejects a wrong shape', () => {
    const { proof } = spend();
    const C = proof.com1[0];
    expect(C).toBeDefined();
    const shapes: SpendMessage[] = [
      { ...proof, com1: proof.com1.slice(1) },
      { ...proof, comC: C },
      { ...proof, s: 0n, com1: [], comC: C },
    ];
    for (const p of shapes)
      expect(code(() => verifySpend(params, skM, ctxCred, ctxSpend, p))).toBe('Verify');
  });

  it('rejects an identity A_prime (soundness-critical, Section 6)', () => {
    const { proof } = spend();
    const Aprime = proof.Aprime.subtract(proof.Aprime);
    expect(code(() => verifySpend(params, skM, ctxCred, ctxSpend, { ...proof, Aprime }))).toBe(
      'Verify'
    );
  });

  it('rejects a refund for another spend', () => {
    const a = spend();
    const b = spend();
    const refund = issueRefund(verifySpend(params, skM, ctxCred, ctxSpend, b.proof), 0n);
    expect(code(() => finalizeRefund(params, pkM, ctxCred, a.state, refund))).toBe('Verify');
    // The state was not consumed by the failure.
    const own = issueRefund(verifySpend(params, skM, ctxCred, ctxSpend, a.proof), 0n);
    expect(finalizeRefund(params, pkM, ctxCred, a.state, own).c).toBe(70n);
  });

  it('rejects a response under another key', () => {
    const other = generateKeys(params);
    const { state, request } = issueRequest(params);
    const response = issueResponse(params, other.skM, ctxCred, 1n, request);
    expect(code(() => finalizeIssue(params, pkM, ctxCred, state, response))).toBe('Verify');
  });

  it('rejects a tampered issuance request', () => {
    const { request } = issueRequest(params);
    const bytes = encodeIssueRequest(request);
    bytes.set([(bytes[40] ?? 0) ^ 1], 40);
    expect(code(() => issueResponse(params, skM, ctxCred, 1n, decodeIssueRequest(bytes)))).toBe(
      'Verify'
    );
  });
});

describe('amounts (Section 4.3)', () => {
  it('rejects out-of-range amounts', () => {
    const cred = issue(100n);
    expect(
      code(() => issueResponse(params, skM, ctxCred, 256n, issueRequest(params).request))
    ).toBe('Amount');
    expect(code(() => proveSpend(params, cred, ctxCred, 101n, 0n, ctxSpend))).toBe('Amount');
    expect(code(() => proveSpend(params, cred, ctxCred, 0n, 156n, ctxSpend))).toBe('Amount');
    expect(code(() => proveSpend(params, cred, ctxCred, -1n, 0n, ctxSpend))).toBe('Amount');
    // The failures did not consume the Credential.
    const { proof } = proveSpend(params, cred, ctxCred, 10n, 20n, ctxSpend);
    const verified = verifySpend(params, skM, ctxCred, ctxSpend, proof);
    expect(code(() => issueRefund(verified, 31n))).toBe('Amount');
  });

  it('rejects s + a >= 2^L before computing the shape', () => {
    const { proof } = proveSpend(params, issue(100n), ctxCred, 30n, 0n, ctxSpend);
    const bytes = encodeSpend(proof);
    bytes.set([0, 0, 0, 0, 0, 0, 0, 200], 40); // a = 200, s + a = 230 < 256 but shape differs
    expect(code(() => decodeSpend(params, bytes))).toBe('Deserialize');
    bytes.set([0, 0, 0, 0, 0, 0, 0, 230], 40); // s + a = 260
    expect(code(() => decodeSpend(params, bytes))).toBe('Amount');
    bytes.set([1, 0, 0, 0, 0, 0, 0, 0], 32); // s >= 2^L
    expect(code(() => decodeSpend(params, bytes))).toBe('Amount');
  });

  it('computes range weights as in the draft', () => {
    expect(rangeWeights(params, 0n)).toEqual([]);
    expect(rangeWeights(params, 255n)).toEqual([1n, 2n, 4n, 8n, 16n, 32n, 64n, 128n]);
    expect(rangeWeights(params, 5n)).toEqual([1n, 2n, 2n]);
    const wide = createParams(64);
    const max = (1n << 64n) - 1n;
    expect(rangeWeights(wide, max)).toHaveLength(64);
  });

  it('handles L = 64 without overflow', () => {
    const wide = createParams(64);
    const max = (1n << 64n) - 1n;
    const { proof } = proveSpend(wide, issue(max, wide), ctxCred, max, 0n, ctxSpend);
    verifySpend(wide, skM, ctxCred, ctxSpend, proof);
    expect(code(() => createParams(65))).toBe('Value');
    expect(code(() => createParams(0))).toBe('Value');
  });
});

describe('single use (Section 6)', () => {
  it('consumes the Credential, the states, and the verified spend', () => {
    const cred = issue(10n);
    const { state, proof } = proveSpend(params, cred, ctxCred, 1n, 0n, ctxSpend);
    expect(code(() => proveSpend(params, cred, ctxCred, 1n, 0n, ctxSpend))).toBe('Value');
    const verified = verifySpend(params, skM, ctxCred, ctxSpend, proof);
    const refund = issueRefund(verified, 1n);
    expect(code(() => issueRefund(verified, 1n))).toBe('Value');
    finalizeRefund(params, pkM, ctxCred, state, refund);
    expect(code(() => finalizeRefund(params, pkM, ctxCred, state, refund))).toBe('Value');

    const issuance = issueRequest(params);
    const response = issueResponse(params, skM, ctxCred, 1n, issuance.request);
    finalizeIssue(params, pkM, ctxCred, issuance.state, response);
    expect(code(() => finalizeIssue(params, pkM, ctxCred, issuance.state, response))).toBe('Value');
  });

  it('only verifySpend creates a VerifiedSpend', () => {
    const { proof } = proveSpend(params, issue(10n), ctxCred, 1n, 0n, ctxSpend);
    // The token is module-private; a look-alike symbol is refused.
    const forge = (): unknown =>
      Reflect.construct(VerifiedSpend, [Symbol('VerifiedSpend'), params, skM, 0n, proof.Kn, proof]);
    expect(forge).toThrow(ACTError);
  });
});

describe('decoding (Section 4.7)', () => {
  const { proof } = proveSpend(params, issue(100n), ctxCred, 0n, 0n, ctxSpend);
  const bytes = encodeSpend(proof);

  it('rejects truncation and trailing bytes', () => {
    expect(code(() => decodeSpend(params, bytes.subarray(0, -1)))).toBe('Deserialize');
    expect(code(() => decodeSpend(params, new Uint8Array([...bytes, 0])))).toBe('Deserialize');
  });

  it('rejects non-canonical scalars and invalid elements', () => {
    const k = bytes.slice();
    k.fill(0xff, 0, 32); // nullifier >= p
    expect(code(() => decodeSpend(params, k))).toBe('Deserialize');
    const pok = bytes.slice();
    pok.fill(0xff, pok.length - 32); // last response >= p
    expect(code(() => decodeSpend(params, pok))).toBe('Deserialize');
    const point = bytes.slice();
    point[48] = 0x04; // not a compressed prefix
    expect(code(() => decodeSpend(params, point))).toBe('Deserialize');
    point[48] = 0x00; // identity encoding
    expect(code(() => decodeSpend(params, point))).toBe('Deserialize');
  });
});

describe('asynchronous API', () => {
  it('runs a full flow and matches the synchronous encodings', async () => {
    const { state, request } = await issueRequestAsync(params);
    const response = await issueResponseAsync(params, skM, ctxCred, 100n, request);
    const credential = await finalizeIssueAsync(params, pkM, ctxCred, state, response);
    const spend = await proveSpendAsync(params, credential, ctxCred, 30n, 10n, ctxSpend);
    // Each proof verifies under the other API.
    verifySpend(params, skM, ctxCred, ctxSpend, spend.proof);
    const verified = await verifySpendAsync(params, skM, ctxCred, ctxSpend, spend.proof);
    const refund = await issueRefundAsync(verified, 35n);
    const next = await finalizeRefundAsync(params, pkM, ctxCred, spend.state, refund);
    expect(next.c).toBe(105n);
  });

  it('refuses concurrent uses of one Credential', async () => {
    const cred = issue(10n);
    const results = await Promise.allSettled([
      proveSpendAsync(params, cred, ctxCred, 1n, 0n, ctxSpend),
      proveSpendAsync(params, cred, ctxCred, 1n, 0n, ctxSpend),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual(['fulfilled', 'rejected']);
  });

  it('does work independent of the hidden balance', async () => {
    // Remainders 0 (all bits zero) and 254 (seven bits set) must cost the same
    // number of WebCrypto key imports, or timing reveals the balance.
    const imports = async (c: bigint): Promise<number> => {
      const spy = vi.spyOn(globalThis.crypto.subtle, 'importKey');
      await proveSpendAsync(params, issue(c), ctxCred, 1n, 0n, ctxSpend);
      const n = spy.mock.calls.filter(([format]) => format === 'pkcs8').length;
      spy.mockRestore();
      return n;
    };
    const zero = await imports(1n);
    expect(zero).toBeGreaterThan(0);
    expect(await imports(255n)).toBe(zero);
  });

  it('rejects what the synchronous API rejects', async () => {
    const { proof } = proveSpend(params, issue(100n), ctxCred, 30n, 0n, ctxSpend);
    await expect(verifySpendAsync(params, skM, enc('epoch-43'), ctxSpend, proof)).rejects.toThrow(
      /Verify/
    );
  });
});
