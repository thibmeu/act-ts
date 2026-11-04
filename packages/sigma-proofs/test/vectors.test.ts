import { readFileSync } from 'node:fs';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import {
  BLS12381,
  type Ciphersuite,
  decodeField,
  deriveSessionId,
  deserializeScalar,
  LinearRelation,
  P256,
  proveBatchable,
  proveCompact,
  spongeInit,
  verifyBatchable,
  verifyCompact,
} from '../src/index.ts';

/** Appendix A of draft-irtf-cfrg-sigma-protocols-03, one record per vector. */
const vectors = readFileSync(new URL('./vectors/sigma-protocols-03.txt', import.meta.url), 'utf8')
  .trim()
  .split('\n\n')
  .map(
    (block) =>
      new Map(
        block.split('\n').map((line) => {
          const [k = '', v = ''] = line.split(' = ');
          return [k, v];
        })
      )
  );

const suites = { [P256.id]: P256, [BLS12381.id]: BLS12381 };

/** The suite without its native backend, so that noble runs every multiplication. */
const withoutNative = ({ mulMany: _native, ...suite }: Ciphersuite): Ciphersuite => suite;
/** Every backend a suite can run on: native (WebCrypto for P-256) and noble. */
const backends = (suite: Ciphersuite): [string, Ciphersuite][] =>
  suite.mulMany
    ? [
        ['native', suite],
        ['noble', withoutNative(suite)],
      ]
    : [['noble', suite]];
const field = (v: Map<string, string>, k: string): string => {
  const value = v.get(k);
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
      if (v.has('SessionId')) expect(bytesToHex(sessionId)).toBe(field(v, 'SessionId'));
      const proof = hexToBytes(field(v, 'NargString'));
      const compact = field(v, 'Flavor') === 'compact';
      for (const [backend, s] of backends(suite)) {
        let accepted: boolean;
        try {
          const relation = LinearRelation.deserialize(s, hexToBytes(field(v, 'Instance')));
          accepted = await (compact ? verifyCompact : verifyBatchable)(sessionId, relation, proof);
        } catch {
          accepted = false;
        }
        expect(accepted, backend).toBe(field(v, 'Expected') === 'accept');
      }
    });

    if (v.has('Witness')) {
      it(`${id} reproves byte for byte, on every backend`, async () => {
        const suite = suites[field(v, 'Ciphersuite')] ?? P256;
        const relation = LinearRelation.deserialize(suite, hexToBytes(field(v, 'Instance')));
        const raw = hexToBytes(field(v, 'Witness'));
        const witness = Array.from({ length: raw.length / suite.Ns }, (_, i) =>
          deserializeScalar(suite, raw.subarray(i * suite.Ns, (i + 1) * suite.Ns))
        );
        expect(bytesToHex(relation.serialize())).toBe(field(v, 'Instance'));
        const nonces = testDrngNonces(
          suite.id,
          field(v, 'Flavor'),
          field(v, 'Relation'),
          witness.length
        );
        const prove = field(v, 'Flavor') === 'compact' ? proveCompact : proveBatchable;
        const sid = deriveSessionId(field(v, 'Tag'));
        for (const [backend, s] of backends(suite)) {
          const rel = LinearRelation.deserialize(s, hexToBytes(field(v, 'Instance')));
          expect(bytesToHex(await prove(sid, rel, witness, nonces)), backend).toBe(
            field(v, 'NargString')
          );
        }
      });
    }
  }
});
