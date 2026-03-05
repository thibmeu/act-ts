import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  // DTS disabled: @noble/curves exports classes with protected members (ep, assertSame, init)
  // which triggers TS4094 "Property of exported anonymous class type may not be private or protected"
  // when tsup tries to inline type references. Use tsc --emitDeclarationOnly if DTS needed.
  dts: false,
  clean: true,
  skipNodeModulesBundle: true,
});
