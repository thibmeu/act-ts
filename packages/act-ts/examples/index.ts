// Runs every example: npm run examples
//
// Each example is a self-contained protocol run, annotated with the message
// flow of draft-schlesinger-mole-ec-act-00, and returns whether it ended in
// the expected state.

import { issuance } from './issuance.example.ts';
import { lifecycle } from './lifecycle.example.ts';
import { spending } from './spending.example.ts';
import { wire } from './wire.example.ts';

const examples: [string, () => Promise<boolean>][] = [
  ['Issuance (Section 4.5)', issuance],
  ['Spending and refund (Section 4.6)', spending],
  ['Credential lifecycle', lifecycle],
  ['Wire and storage encodings (Section 4.7)', wire],
];

let failed = 0;
for (const [name, run] of examples) {
  console.log(name);
  const ok = await run().catch((e: unknown) => {
    console.error(e);
    return false;
  });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}\n`);
  if (!ok) failed++;
}
process.exit(failed === 0 ? 0 : 1);
