# sigma-proofs

Sigma Protocols for zero-knowledge proofs in TypeScript.

**Specification:** [draft-irtf-cfrg-sigma-protocols-01](https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/)

**Features:**
- LinearRelation constraint system for composable proofs
- Interactive SchnorrProof with prover/verifier/simulator
- Non-interactive proofs via Fiat-Shamir (SHAKE128 sponge)
- Ristretto255 and P-256 ciphersuites

## Installation

```bash
npm install sigma-proofs
```

## Quick Start

Prove knowledge of a discrete logarithm: `PoK{(x): X = x·G}`

```typescript
import { LinearRelation, SchnorrProof, ristretto255 } from 'sigma-proofs';

const group = ristretto255;

// 1. Define the relation
const relation = new LinearRelation(group);
const [varX] = relation.allocateScalars(1); // secret scalar x
const [varG, varXPoint] = relation.allocateElements(2); // G, X
relation.appendEquation(varXPoint, [[varX, varG]]); // X = x·G

// 2. Set public values
const G = group.generator();
const x = group.randomScalar(); // secret
const X = G.multiply(x); // public

relation.setElements([
  [varG, G],
  [varXPoint, X],
]);
// Image is derived automatically from element assignments

// 3. Create proof (interactive)
const proof = new SchnorrProof(relation);
const prover = proof.proverCommit([x]); // returns ProverCommitment
const challenge = group.randomScalar(); // from verifier
const response = prover.respond(challenge); // one-shot, consumes state

// 4. Verify
const valid = proof.verify(prover.commitment, challenge, response);
console.log('Valid:', valid); // true
```

## Concepts

### Camenisch-Stadler Notation

This library uses index-based constraint systems that correspond to [Camenisch-Stadler notation](https://crypto.ethz.ch/publications/files/CamSta97b.pdf):

| Notation                      | Meaning                                              |
| ----------------------------- | ---------------------------------------------------- |
| `PoK{(x): X = x·G}`           | Proof of knowledge of scalar `x` such that `X = x·G` |
| `PoK{(x): X = x·G ∧ Y = x·H}` | DLEQ: same `x` for both equations                    |
| `PoK{(x,r): C = x·G + r·H}`   | Pedersen commitment opening                          |

### LinearRelation

A constraint system of linear equations over a group:

```typescript
const relation = new LinearRelation(group);

// Allocate variables (returns indices)
const [varX, varR] = relation.allocateScalars(2); // secret witnesses
const [varG, varH, varC] = relation.allocateElements(3); // public elements

// Add constraint: C = x·G + r·H
// The LHS element (varC) becomes the image for this equation
relation.appendEquation(varC, [
  [varX, varG], // coefficient varX, element varG
  [varR, varH],
]);

// Set concrete values - image is derived automatically
relation.setElements([
  [varG, G],
  [varH, H],
  [varC, C],
]);
// relation.image is now [C] (derived from varC in appendEquation)
```

### Interactive Protocol

The Schnorr protocol is a 3-move interactive proof:

1. **Prover** → `commitment` (randomized statement)
2. **Verifier** → `challenge` (random scalar)
3. **Prover** → `response` (computed from witness + challenge)

For non-interactive proofs, apply Fiat-Shamir: hash the commitment to derive the challenge.

## Ciphersuites

| Ciphersuite    | Import                                                | Use Case                           |
| -------------- | ----------------------------------------------------- | ---------------------------------- |
| `ristretto255` | `import { ristretto255 } from '@aspect/sigma-proofs'` | Recommended for new applications   |
| `p256`         | `import { p256 } from '@aspect/sigma-proofs'`         | NIST compliance, WebCrypto interop |

### Adding Custom Groups

Implement the `Group` interface:

```typescript
interface Group {
  readonly name: string;
  readonly scalarSize: number;
  readonly elementSize: number;
  readonly order: bigint;

  identity(): GroupElement;
  generator(): GroupElement;
  randomScalar(): Scalar;
  scalarFromBigint(n: bigint): Scalar;
  scalarFromBytes(bytes: Uint8Array): Scalar;
  elementFromBytes(bytes: Uint8Array): GroupElement;
  msm(scalars: Scalar[], elements: GroupElement[]): GroupElement;
}
```

## Examples

See [`examples/`](./examples/) for complete working examples:

- `schnorr.ts` - Basic discrete log proof
- `dleq.ts` - Discrete log equality proof
- `pedersen.ts` - Pedersen commitment opening

## API Reference

### LinearRelation

```typescript
class LinearRelation {
  constructor(group: Group);
  allocateScalars(count: number): number[];
  allocateElements(count: number): number[];
  appendEquation(lhs: number, rhs: [number, number][]): void;
  setElements(assignments: [number, GroupElement][]): void;
  get image(): readonly GroupElement[]; // derived from imageIndices
}
```

### SchnorrProof

```typescript
class SchnorrProof {
  constructor(relation: LinearRelation);
  proverCommit(witness: Scalar[]): ProverCommitment;
  verify(commitment: Commitment, challenge: Scalar, response: Response): boolean;
  serializeCommitment(c: Commitment): Uint8Array;
  deserializeCommitment(bytes: Uint8Array): Commitment;
  serializeResponse(r: Response): Uint8Array;
  deserializeResponse(bytes: Uint8Array): Response;
}

interface ProverCommitment {
  readonly commitment: Commitment;
  respond(challenge: Scalar): Response; // one-shot, throws on reuse
}
```

## Security Considerations

### Interactive vs Non-Interactive

This library implements **interactive** sigma protocols. The verifier must provide a fresh random challenge. For non-interactive proofs:

1. Use Fiat-Shamir heuristic: `challenge = Hash(commitment || statement)`
2. Include protocol and instance identifiers in the hash
3. Use a cryptographic hash function (SHA-256, BLAKE3)

### Constant-Time Operations

From [@noble/curves](https://github.com/paulmillr/noble-curves):

> JIT-compiler and Garbage Collector make "constant time" extremely hard to achieve in JavaScript.

This implementation is suitable for:

- Demonstrations and prototypes
- Interoperability testing
- Client-side applications where timing attacks are less relevant

For high-security server applications, consider native implementations.

### Challenge Generation

The challenge must be:

- Unpredictable to the prover before commitment
- Uniformly random in the scalar field
- Fresh for each proof

## Spec Compliance

Based on [draft-irtf-cfrg-sigma-protocols-01](https://www.ietf.org/archive/id/draft-irtf-cfrg-sigma-protocols-01.txt).

**Implemented:**

- Group abstraction (§2.1)
- LinearMap with Yale sparse format (§2.2.2)
- LinearRelation constraint system (§2.2.3)
- SchnorrProof protocol (§2.2.4-6)
- P-256 ciphersuite (§2.3.1)
- Ristretto255 ciphersuite (for ACT)

**Implemented:**

- Simulator functions (`simulateResponse`, `simulateCommitment`, `simulate`)
- Fiat-Shamir transformation (draft-irtf-cfrg-fiat-shamir-01)
  - SHAKE128 duplex sponge
  - ByteCodec for absorb/squeeze
  - NISigmaProtocol for non-interactive proofs

**Not yet implemented:**

- OR-composition
- BLS12-381 ciphersuite (spec test vectors use this)
- Statement serialization for instance labels
- Native MSM optimization
- Test vector generation (for cross-implementation validation)

## Roadmap

### Near-term

- [ ] BLS12-381 ciphersuite (required for spec test vectors)
- [ ] Statement/instance label serialization per Fiat-Shamir spec §4
- [ ] Import VOPRF DLEQ test vectors from RFC 9497

### Future

- [ ] OR-composition for disjunctive proofs
- [ ] Native MSM for performance
- [ ] Test vector export (JSON format compatible with reference implementations)

## License

Apache-2.0
