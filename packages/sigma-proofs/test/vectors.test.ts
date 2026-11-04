import { readFileSync } from 'node:fs';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import {
  BLS12381,
  LinearRelation,
  P256,
  decodeField,
  deriveSessionId,
  deserializeScalar,
  proveBatchable,
  proveBatchableAsync,
  proveCompact,
  proveCompactAsync,
  spongeInit,
  verifyBatchable,
  verifyBatchableAsync,
  verifyCompact,
  verifyCompactAsync,
} from '../src/index.js';

/** Appendix A of draft-irtf-cfrg-sigma-protocols-03, one record per vector. */
const vectors = readFileSync(new URL('./vectors/sigma-protocols-03.txt', import.meta.url), 'utf8')
  .trim()
  .split('\n\n')
  .map((block) =>
    Object.fromEntries(
      block.split('\n').map((line) => {
        const [k = '', v = ''] = line.split(' = ');
        return [k, v];
      })
    )
  );

const suites = { [P256.id]: P256, [BLS12381.id]: BLS12381 };
const field = (v: Record<string, string>, k: string): string => {
  const value = v[k];
  if (value === undefined) throw new Error(`missing ${k}`);
  return value;
};

/** Appendix A.1: the prover randomness, squeezed Ns + 16 bytes at a time. */
function testDrngNonces(suiteId: string, flavor: string, relation: string, count: number) {
  const suite = suites[suiteId] ?? P256;
  const marker = flavor === 'compact' ? 'CMPT' : 'DSFS';
  const xof = spongeInit(deriveSessionId(`TestDRNG-SIGMA-PROOFS-${marker}-${suiteId}-${relation}`));
  const stream = xof.xof(count * (suite.Ns + 16));
  return Array.from({ length: count }, (_, i) =>
    decodeField(suite, stream.subarray(i * (suite.Ns + 16), (i + 1) * (suite.Ns + 16)))
  );
}

describe('draft-irtf-cfrg-sigma-protocols-03 vectors', () => {
  it('parses all 75 vectors', () => {
    expect(vectors).toHaveLength(75);
  });

  for (const v of vectors) {
    const id = field(v, 'Id');
    it(`${id} -> ${field(v, 'Expected')}`, async () => {
      const suite = suites[field(v, 'Ciphersuite')];
      if (!suite) throw new Error('unknown suite');
      const sessionId = deriveSessionId(field(v, 'Tag'));
      if (v.SessionId) expect(bytesToHex(sessionId)).toBe(v.SessionId);
      const proof = hexToBytes(field(v, 'NargString'));
      const compact = field(v, 'Flavor') === 'compact';
      let accepted: boolean;
      let acceptedAsync: boolean;
      try {
        const relation = LinearRelation.deserialize(suite, hexToBytes(field(v, 'Instance')));
        accepted = (compact ? verifyCompact : verifyBatchable)(sessionId, relation, proof);
        acceptedAsync = await (compact ? verifyCompactAsync : verifyBatchableAsync)(
          sessionId,
          relation,
          proof
        );
      } catch {
        accepted = acceptedAsync = false;
      }
      expect(accepted).toBe(field(v, 'Expected') === 'accept');
      expect(acceptedAsync).toBe(accepted);
    });

    if (v.Witness) {
      it(`${id} reproves byte for byte, sync and async`, async () => {
        const suite = suites[field(v, 'Ciphersuite')] ?? P256;
        const relation = LinearRelation.deserialize(suite, hexToBytes(field(v, 'Instance')));
        const raw = hexToBytes(field(v, 'Witness'));
        const witness = Array.from({ length: raw.length / suite.Ns }, (_, i) =>
          deserializeScalar(suite, raw.subarray(i * suite.Ns, (i + 1) * suite.Ns))
        );
        expect(bytesToHex(relation.serialize())).toBe(v.Instance);
        const nonces = testDrngNonces(
          suite.id,
          field(v, 'Flavor'),
          field(v, 'Relation'),
          witness.length
        );
        const compact = field(v, 'Flavor') === 'compact';
        const sid = deriveSessionId(field(v, 'Tag'));
        const proof = (compact ? proveCompact : proveBatchable)(sid, relation, witness, nonces);
        expect(bytesToHex(proof)).toBe(v.NargString);
        const proofAsync = await (compact ? proveCompactAsync : proveBatchableAsync)(
          sid,
          relation,
          witness,
          nonces
        );
        expect(bytesToHex(proofAsync)).toBe(v.NargString);
      });
    }
  }
});
