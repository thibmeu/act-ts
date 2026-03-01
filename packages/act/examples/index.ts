// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

/**
 * ACT Examples Runner
 *
 * Run all examples: npx tsx examples/index.ts
 * Run individual: npx tsx examples/issuance.ts
 */

import { issuanceExample } from './issuance.js';
import { spendingExample } from './spending.js';
import { fullFlowExample } from './full-flow.js';
import { wireFormatExample } from './wire-format.js';

async function main(): Promise<void> {
  console.log('Anonymous Credit Tokens (ACT) - Examples\n');
  console.log('========================================\n');

  await issuanceExample();
  console.log('\n----------------------------------------\n');

  await spendingExample();
  console.log('\n----------------------------------------\n');

  await fullFlowExample();
  console.log('\n----------------------------------------\n');

  await wireFormatExample();
}

main().catch(console.error);
