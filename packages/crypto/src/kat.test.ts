// Known-answer tests: the pinned KEM library must match published vectors byte for byte.
// vectors/ml-kem-768-*.json: NIST ACVP FIPS 203 (ML-KEM-768 groups only).
// vectors/xwing-draft-10.json: draft-connolly-cfrg-xwing-kem-10, Appendix C.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

type Vec = Record<string, string> & { tcId: number; testPassed: boolean };
interface Group {
  function?: string;
  tests: Vec[];
}

function load<T>(name: string): T {
  return JSON.parse(readFileSync(new URL(`./vectors/${name}`, import.meta.url), 'utf8')) as T;
}
const hex = (s: string | undefined): Uint8Array => new Uint8Array(Buffer.from(s ?? '', 'hex'));

test('ML-KEM-768 keygen matches NIST ACVP vectors', () => {
  const { testGroups } = load<{ testGroups: Group[] }>('ml-kem-768-keygen.json');
  const tests = testGroups.flatMap((g) => g.tests);
  assert.equal(tests.length, 25);
  for (const t of tests) {
    // FIPS 203: seed = d || z
    const { publicKey, secretKey } = ml_kem768.keygen(new Uint8Array([...hex(t.d), ...hex(t.z)]));
    assert.deepEqual(publicKey, hex(t.ek), `keygen #${t.tcId} ek`);
    assert.deepEqual(secretKey, hex(t.dk), `keygen #${t.tcId} dk`);
  }
});

test('ML-KEM-768 encapsulation, decapsulation and key checks match NIST ACVP vectors', () => {
  const { testGroups } = load<{ testGroups: Group[] }>('ml-kem-768-encap-decap.json');
  const seen: Record<string, number> = {};
  for (const g of testGroups) {
    const fn = g.function ?? '';
    for (const t of g.tests) {
      const id = `${fn} #${t.tcId}`;
      seen[fn] = (seen[fn] ?? 0) + 1;
      if (fn === 'encapsulation') {
        const { cipherText, sharedSecret } = ml_kem768.encapsulate(hex(t.ek), hex(t.m));
        assert.deepEqual(cipherText, hex(t.c), id);
        assert.deepEqual(sharedSecret, hex(t.k), id);
      } else if (fn === 'decapsulation') {
        // includes implicit rejection: a bad ciphertext must give the pseudo-random reject key
        assert.deepEqual(ml_kem768.decapsulate(hex(t.c), hex(t.dk)), hex(t.k), id);
      } else if (fn === 'encapsulationKeyCheck') {
        const run = () => ml_kem768.encapsulate(hex(t.ek));
        if (t.testPassed) assert.doesNotThrow(run, id);
        else assert.throws(run, id);
      } else if (fn === 'decapsulationKeyCheck') {
        const run = () => ml_kem768.decapsulate(new Uint8Array(1088), hex(t.dk));
        if (t.testPassed) assert.doesNotThrow(run, id);
        else assert.throws(run, id);
      } else {
        assert.fail(`unknown ACVP function ${fn}`);
      }
    }
  }
  assert.deepEqual(seen, {
    encapsulation: 25,
    decapsulation: 10,
    decapsulationKeyCheck: 10,
    encapsulationKeyCheck: 10,
  });
});

test('X-Wing matches the draft test vectors', () => {
  const vectors = load<Record<string, string>[]>('xwing-draft-10.json');
  assert.equal(vectors.length, 3);
  for (const [i, v] of vectors.entries()) {
    const { publicKey, secretKey } = xwing.keygen(hex(v.seed));
    assert.deepEqual(secretKey, hex(v.sk), `#${i} sk`);
    assert.deepEqual(publicKey, hex(v.pk), `#${i} pk`);
    const { cipherText, sharedSecret } = xwing.encapsulate(publicKey, hex(v.eseed));
    assert.deepEqual(cipherText, hex(v.ct), `#${i} ct`);
    assert.deepEqual(sharedSecret, hex(v.ss), `#${i} ss`);
    assert.deepEqual(xwing.decapsulate(hex(v.ct), hex(v.sk)), hex(v.ss), `#${i} decap`);
  }
});
