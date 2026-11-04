// Benchmarks: npm run bench (vitest 5 benchmark project)
//
// An ordinary spend (s > 0, a = 0) and its verification at a small and the
// largest balance width. Proving includes issuing the Credential it consumes.

import { test } from 'vitest';
import {
  type Credential,
  createParams,
  finalizeIssue,
  generateKeys,
  issueRequest,
  issueResponse,
  proveSpend,
  verifySpend,
} from '../src/index.ts';

const ctxCred = new TextEncoder().encode('bench-context');
const ctxSpend = new TextEncoder().encode('bench-challenge');

for (const L of [8, 64]) {
  const params = createParams(L);
  const { skM, pkM } = await generateKeys(params);
  const credential = async (): Promise<Credential> => {
    const { state, request } = await issueRequest(params);
    const response = await issueResponse(params, skM, ctxCred, 100n, request);
    return finalizeIssue(params, pkM, ctxCred, state, response);
  };
  const { proof } = await proveSpend(params, await credential(), ctxCred, 30n, 0n, ctxSpend);

  test(`L = ${L}`, async ({ bench }) => {
    await bench.compare(
      bench('proveSpend', async () => {
        await proveSpend(params, await credential(), ctxCred, 30n, 0n, ctxSpend);
      }),
      bench('verifySpend', async () => {
        await verifySpend(params, skM, ctxCred, ctxSpend, proof);
      })
    );
  });
}
