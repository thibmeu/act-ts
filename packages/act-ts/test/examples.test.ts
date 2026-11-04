import { describe, expect, it, vi } from 'vitest';
import { issuance } from '../examples/issuance.example.ts';
import { lifecycle } from '../examples/lifecycle.example.ts';
import { spending } from '../examples/spending.example.ts';
import { wire } from '../examples/wire.example.ts';

describe('examples', () => {
  vi.spyOn(console, 'log').mockImplementation(() => undefined);
  it.each([
    ['issuance', issuance],
    ['spending', spending],
    ['lifecycle', lifecycle],
    ['wire', wire],
  ])('%s ends in the expected state', async (_, run) => {
    expect(await run()).toBe(true);
  });
});
