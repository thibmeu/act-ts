import { bench, describe } from 'vitest';
import {
  createParams,
  finalizeIssue,
  finalizeRefund,
  generateKeys,
  issueRefund,
  issueRequest,
  issueResponse,
  proveSpend,
  proveSpendAsync,
  verifySpend,
  verifySpendAsync,
  type Credential,
} from '../src/index.js';

const ctxCred = new TextEncoder().encode('bench-context');
const ctxSpend = new TextEncoder().encode('bench-challenge');

for (const L of [8, 64]) {
  describe(`L = ${L}`, () => {
    const params = createParams(L);
    const { skM, pkM } = generateKeys(params);
    const credential = (): Credential => {
      const { state, request } = issueRequest(params);
      return finalizeIssue(
        params,
        pkM,
        ctxCred,
        state,
        issueResponse(params, skM, ctxCred, 100n, request)
      );
    };
    const { request } = issueRequest(params);
    const spend = proveSpend(params, credential(), ctxCred, 30n, 0n, ctxSpend);

    bench('issueRequest', () => void issueRequest(params));
    bench('issueResponse', () => void issueResponse(params, skM, ctxCred, 100n, request));
    bench('proveSpend', () => void proveSpend(params, credential(), ctxCred, 30n, 0n, ctxSpend));
    bench(
      'proveSpend (refresh)',
      () => void proveSpend(params, credential(), ctxCred, 0n, 0n, ctxSpend)
    );
    bench('verifySpend', () => void verifySpend(params, skM, ctxCred, ctxSpend, spend.proof));
    bench('proveSpendAsync', async () => {
      await proveSpendAsync(params, credential(), ctxCred, 30n, 0n, ctxSpend);
    });
    bench('verifySpendAsync', async () => {
      await verifySpendAsync(params, skM, ctxCred, ctxSpend, spend.proof);
    });
    bench('issueRefund + finalizeRefund', () => {
      const s = proveSpend(params, credential(), ctxCred, 30n, 0n, ctxSpend);
      const refund = issueRefund(verifySpend(params, skM, ctxCred, ctxSpend, s.proof), 5n);
      finalizeRefund(params, pkM, ctxCred, s.state, refund);
    });
  });
}
