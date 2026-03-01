import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/index-vnext.ts'],
  format: ['esm'],
  // DTS disabled: strict TS errors in vnext code need fixing
  // TODO: re-enable once issuance-vnext.ts and spend-vnext.ts are fixed
  dts: false,
  clean: true,
  skipNodeModulesBundle: true,
});
