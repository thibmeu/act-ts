# /review-crypto

**Persona**: Cryptographic Library Maintainer (noble-curves style)

**Focus**: Implementation quality, API patterns, low-level correctness.

## Checklist

- `Uint8Array` used consistently (not hex strings in APIs)
- Scalar/point operations use library primitives correctly
- No timing side-channels in application code (beyond library limitations)
- Proper cleanup of sensitive material where possible
- API ergonomics match noble-curves conventions
- Types from `@noble/curves` used directly, not rewrapped
- XOF usage (Blake3) follows spec domain separation

## Code Patterns

```typescript
// Good: Uint8Array in/out
function sign(msg: Uint8Array): Uint8Array;

// Bad: hex strings
function sign(msg: string): string;

// Good: direct noble types
import { RistrettoPoint } from '@noble/curves/ed25519';

// Bad: rewrapping
type Point = { x: bigint; y: bigint };
```

## Sample Questions

- Is this scalar operation constant-time in the library?
- Could this error message leak timing information?
- Does this match the API style of @noble/curves?
