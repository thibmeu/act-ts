import { readFileSync } from 'node:fs';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import {
  contextScalar,
  createParams,
  decodeIssueRequest,
  decodeIssueResponse,
  decodeRefund,
  decodeSpend,
  encodeCredential,
  encodeIssuanceState,
  encodeIssueRequest,
  encodeIssueResponse,
  encodePublicKey,
  encodeRefund,
  encodeSpend,
  encodeSpendState,
  finalizeIssue,
  finalizeRefund,
  generateKeys,
  issueRefund,
  issueRequest,
  issueResponse,
  proveSpend,
  type Random,
  verifySpend,
} from '../src/index.ts';

/** The draft's `key = value` format, with hex continuation lines. */
function parse(name: string): Map<string, string> {
  const text = readFileSync(new URL(`./vectors/${name}`, import.meta.url), 'utf8');
  const out = new Map<string, string>();
  let key = '';
  for (const line of text.split('\n')) {
    const m = /^(\S+) =\s*(.*)$/.exec(line);
    if (m) {
      key = m[1] ?? '';
      out.set(key, m[2] ?? '');
    } else if (line.trim()) out.set(key, (out.get(key) ?? '') + line.trim());
  }
  return out;
}

/** Serves the recorded bytes in place of random, and checks all were used. */
function replay(hex: string): Random & { done(): boolean } {
  const bytes = hexToBytes(hex);
  let off = 0;
  const rng = (n: number): Uint8Array => {
    if (off + n > bytes.length) throw new Error('vector randomness exhausted');
    off += n;
    return bytes.slice(off - n, off);
  };
  return Object.assign(rng, { done: () => off === bytes.length });
}

const ACT_RS_CTX = 'ACTv1-P256-SHA256';

const files = [
  // draft-schlesinger-mole-ec-act-00, Appendix A (ctx_proto EC-ACTv1-P256-SHA256)
  'ec-act-00-L4.txt',
  // act-rs at 79eb93d (pre-publication ctx_proto ACTv1-P256-SHA256)
  'draft-L4.txt',
  'act-L1.txt',
  'act-L2.txt',
  'act-L8.txt',
  'act-L16.txt',
  'act-L64.txt',
];

describe.each(files)('%s', (file) => {
  const v = parse(file);
  const get = (k: string): string => {
    const value = v.get(k);
    if (value === undefined) throw new Error(`missing ${k}`);
    return value;
  };
  const hex = (k: string): Uint8Array => hexToBytes(get(k));
  const int = (k: string): bigint => BigInt(get(k));

  it('replays every entry byte for byte', async () => {
    // act-rs's generated files omit the suite entries; they use its context.
    const ctxProto = v.has('suite.ctx_proto') ? hex('suite.ctx_proto') : utf8ToBytes(ACT_RS_CTX);
    const params = createParams(Number(get('suite.L')), { protocolContext: ctxProto });
    const ctxCred = hex('suite.ctx_cred');
    if (v.has('suite.H1')) {
      for (const h of ['H1', 'H2', 'H3', 'H4'] as const) {
        expect(bytesToHex(params[h].toBytes(true)), h).toBe(get(`suite.${h}`));
      }
      expect(contextScalar(params, ctxCred).toString(16).padStart(64, '0')).toBe(get('suite.ctx'));
    }

    const keyRng = replay(get('key.rand'));
    const { skM, pkM } = await generateKeys(params, keyRng);
    expect(keyRng.done()).toBe(true);
    expect(skM.toString(16).padStart(64, '0')).toBe(get('key.skM'));
    expect(bytesToHex(encodePublicKey(pkM))).toBe(get('key.pkM'));

    let rng = replay(get('issue.request.rand'));
    const { state, request } = await issueRequest(params, rng);
    expect(rng.done()).toBe(true);
    expect(bytesToHex(encodeIssuanceState(state))).toBe(get('issue.request.state'));
    expect(bytesToHex(encodeIssueRequest(request))).toBe(get('issue.request.message'));

    rng = replay(get('issue.response.rand'));
    const response = await issueResponse(
      params,
      skM,
      ctxCred,
      int('issue.response.c'),
      decodeIssueRequest(hex('issue.request.message')),
      rng
    );
    expect(rng.done()).toBe(true);
    expect(bytesToHex(encodeIssueResponse(response))).toBe(get('issue.response.message'));

    let credential = await finalizeIssue(
      params,
      pkM,
      ctxCred,
      state,
      decodeIssueResponse(params, hex('issue.response.message'))
    );
    expect(bytesToHex(encodeCredential(credential))).toBe(get('issue.credential'));

    let spends = 0;
    for (let i = 1; v.has(`spend${i}.s`); i++, spends++) {
      const p = `spend${i}`;
      const ctxSpend = hex(`${p}.ctx_spend`);
      rng = replay(get(`${p}.rand`));
      const { state: spendState, proof } = await proveSpend(
        params,
        credential,
        ctxCred,
        int(`${p}.s`),
        int(`${p}.a`),
        ctxSpend,
        rng
      );
      expect(rng.done()).toBe(true);
      expect(bytesToHex(encodeSpendState(spendState)), `${p}.state`).toBe(get(`${p}.state`));
      expect(bytesToHex(encodeSpend(proof)), `${p}.message`).toBe(get(`${p}.message`));

      const verified = await verifySpend(
        params,
        skM,
        ctxCred,
        ctxSpend,
        decodeSpend(params, hex(`${p}.message`))
      );
      rng = replay(get(`${p}.refund.rand`));
      const refund = await issueRefund(verified, int(`${p}.refund.t`), rng);
      expect(rng.done()).toBe(true);
      expect(bytesToHex(encodeRefund(refund)), `${p}.refund`).toBe(get(`${p}.refund.message`));

      credential = await finalizeRefund(
        params,
        pkM,
        ctxCred,
        spendState,
        decodeRefund(params, hex(`${p}.refund.message`))
      );
      expect(bytesToHex(encodeCredential(credential)), `${p}.credential`).toBe(
        get(`${p}.credential`)
      );
    }
    expect(spends).toBeGreaterThanOrEqual(4);
  });
});
