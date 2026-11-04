# sigma-proofs

Sigma protocols for linear relations ([draft-irtf-cfrg-sigma-protocols-03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/03/)) under the SHAKE128 duplex sponge of [draft-irtf-cfrg-fiat-shamir-03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/03/), with compact and batchable NARG strings.

Ciphersuites: `sigma-proofs_Shake128_P256` and `sigma-proofs_Shake128_BLS12381`, on [@noble/curves](https://github.com/paulmillr/noble-curves).

```typescript
import { LinearRelation, P256, deriveSessionId, proveCompact, verifyCompact } from 'sigma-proofs';

// DLEQ: X = x * G and Y = x * H. Element 0 is the generator G.
const rel = new LinearRelation(P256);
const h = rel.addElements(H, X, Y); // indices h, h + 1, h + 2
rel.addEquation([[h + 1, 1n]], [[0, 0, 1n]]); // image: X      terms: x * G
rel.addEquation([[h + 2, 1n]], [[0, h, 1n]]); // image: Y      terms: x * H

const sid = deriveSessionId('MYAPP-V01-dleq-CMPT-with-sigma-proofs_Shake128_P256');
const proof = proveCompact(sid, rel, [x]);
verifyCompact(sid, rel, proof); // true
```

`LinearRelation.serialize()` and `LinearRelation.deserialize()` implement `SerializeLinearRelation`; `validate()` implements `ValidateInstance` and runs inside every prover and verifier. All 75 vectors of the draft's Appendix A pass, and every valid proof is reproduced byte for byte.
