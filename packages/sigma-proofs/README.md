# sigma-proofs

Sigma protocols for linear relations ([draft-irtf-cfrg-sigma-protocols-03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/03/)) under the SHAKE128 duplex sponge of [draft-irtf-cfrg-fiat-shamir-03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/03/), with compact and batchable NARG strings.

Ciphersuites: `sigma-proofs_Shake128_P256` and `sigma-proofs_Shake128_BLS12381`, on [@noble/curves](https://github.com/paulmillr/noble-curves).

```typescript
import {
  LinearRelation,
  P256,
  deriveSessionId,
  proveCompact,
  randomNonces,
  verifyCompact,
} from 'sigma-proofs';

// DLEQ: X = x * G and Y = x * H.
const [x = 1n, h = 1n] = randomNonces(P256, 2); // a witness and a demo base
const G = P256.Point.BASE;
const H = G.multiply(h);
const [X, Y] = [G.multiply(x), H.multiply(x)];

// Element 0 is the generator G; addElements returns the first new index.
const rel = new LinearRelation(P256);
const iH = rel.addElements(H, X, Y); // H, X, Y at iH, iH + 1, iH + 2
rel.addEquation([[iH + 1, 1n]], [[0, 0, 1n]]); // X = x * G   (image; terms [scalar, element, coeff])
rel.addEquation([[iH + 2, 1n]], [[0, iH, 1n]]); // Y = x * H

const sid = deriveSessionId('MYAPP-V01-dleq-CMPT-with-sigma-proofs_Shake128_P256');
const proof = await proveCompact(sid, rel, [x]);
await verifyCompact(sid, rel, proof); // true
```

`LinearRelation.serialize()` and `LinearRelation.deserialize()` implement `SerializeLinearRelation`; `validate()` implements `ValidateInstance` and runs inside every prover and verifier. All 75 vectors of the draft's Appendix A pass, and every valid proof is reproduced byte for byte.

Provers and verifiers are `async`: each round of scalar multiplications runs as one batch, on WebCrypto for P-256 and on noble otherwise, with identical outputs. `mulMany` exposes the same batching to protocols built on top, as act-ts does. `registerFixedBase` marks a long-lived point for noble's precomputed table.
