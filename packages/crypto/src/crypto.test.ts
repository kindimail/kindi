import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  Algorithm,
  VERSION,
  decodeHeader,
  decrypt,
  encodeHeader,
  encrypt,
  generateMailboxKeyPair,
  openKey,
  sealKey,
} from './index.ts';

const key = new Uint8Array(32).fill(7);
const keyId = new TextEncoder().encode('k1');
const msg = new TextEncoder().encode('hello kindi');
const HDR = 3 + keyId.length;

test('header round trip', () => {
  const h = { version: VERSION, algorithm: Algorithm.XChaCha20Poly1305, keyId };
  const { header, length } = decodeHeader(encodeHeader(h));
  assert.deepEqual(header, h);
  assert.equal(length, HDR);
});

test('header rejects bad version, algorithm, truncation and long keyId', () => {
  assert.throws(() => decodeHeader(new Uint8Array([9, 1, 0])), /version/);
  assert.throws(() => decodeHeader(new Uint8Array([1, 99, 0])), /algorithm/);
  assert.throws(() => decodeHeader(new Uint8Array([1, 1, 5, 0])), /short/);
  assert.throws(() => decodeHeader(new Uint8Array([1])), /short/);
  assert.throws(() => encrypt(key, msg, new Uint8Array(256)), /too long/);
});

test('aead round trip, with and without aad, including empty plaintext', () => {
  assert.deepEqual(decrypt(key, encrypt(key, msg, keyId), keyId), msg);
  assert.deepEqual(decrypt(key, encrypt(key, new Uint8Array(), keyId), keyId), new Uint8Array());
  const aad = new Uint8Array([1, 2, 3]);
  assert.deepEqual(decrypt(key, encrypt(key, msg, keyId, aad), keyId, aad), msg);
});

test('aead rejects wrong key, wrong aad, wrong keyId, bad key length', () => {
  const rec = encrypt(key, msg, keyId);
  assert.throws(() => decrypt(new Uint8Array(32).fill(8), rec, keyId));
  assert.throws(() => decrypt(key, rec, keyId, new Uint8Array([1])));
  assert.throws(() => decrypt(key, rec, new TextEncoder().encode('k2')), /mismatch/);
  assert.throws(() => decrypt(new Uint8Array(16), rec, keyId), /32 bytes/);
  assert.throws(() => encrypt(new Uint8Array(31), msg, keyId), /32 bytes/);
});

test('aead rejects any flipped byte, any truncation and trailing bytes', () => {
  const rec = encrypt(key, msg, keyId);
  for (let i = 0; i < rec.length; i++) {
    const bad = rec.slice();
    bad[i] = bad[i]! ^ 1;
    assert.throws(() => decrypt(key, bad, keyId), `byte ${i} was not detected`);
  }
  for (let n = 0; n < rec.length; n++) {
    assert.throws(() => decrypt(key, rec.subarray(0, n), keyId), `length ${n} was accepted`);
  }
  assert.throws(() => decrypt(key, new Uint8Array([...rec, 0]), keyId));
});

test('aead uses a fresh nonce each time', () => {
  assert.notDeepEqual(encrypt(key, msg, keyId), encrypt(key, msg, keyId));
});

test('X-Wing key sizes match the constants used in seal.ts', () => {
  const kp = generateMailboxKeyPair();
  assert.equal(kp.publicKey.length, 1216);
  assert.equal(kp.secretKey.length, 32);
});

test('seal and open a CEK', () => {
  const kp = generateMailboxKeyPair();
  const cek = crypto.getRandomValues(new Uint8Array(32));
  const sealed = sealKey(kp.publicKey, cek, keyId);
  assert.deepEqual(openKey(kp.secretKey, sealed, keyId), cek);
});

test('open rejects another mailbox key, wrong keyId and wrong key lengths', () => {
  const kp = generateMailboxKeyPair();
  const other = generateMailboxKeyPair();
  const cek = crypto.getRandomValues(new Uint8Array(32));
  const sealed = sealKey(kp.publicKey, cek, keyId);
  assert.throws(() => openKey(other.secretKey, sealed, keyId));
  assert.throws(() => openKey(kp.secretKey, sealed, new TextEncoder().encode('k2')), /mismatch/);
  assert.throws(() => openKey(new Uint8Array(31), sealed, keyId), /length/);
  assert.throws(() => sealKey(new Uint8Array(10), cek, keyId), /length/);
  assert.throws(() => sealKey(kp.publicKey, new Uint8Array(31), keyId), /32 bytes/);
});

test('open rejects tampering, truncation and trailing bytes', () => {
  const kp = generateMailboxKeyPair();
  const sealed = sealKey(kp.publicKey, crypto.getRandomValues(new Uint8Array(32)), keyId);
  assert.equal(sealed.length, HDR + 1120 + 24 + 32 + 16);
  // header, nonce and tag: every byte. KEM ciphertext: a spread of offsets.
  const offsets = new Set<number>();
  for (let i = 0; i < HDR; i++) offsets.add(i);
  for (let i = HDR; i < HDR + 1120; i += 37) offsets.add(i);
  offsets.add(HDR + 1119);
  for (let i = HDR + 1120; i < sealed.length; i++) offsets.add(i);
  for (const i of offsets) {
    const bad = sealed.slice();
    bad[i] = bad[i]! ^ 1;
    assert.throws(() => openKey(kp.secretKey, bad, keyId), `byte ${i} was not detected`);
  }
  for (const n of [0, 2, HDR, HDR + 100, HDR + 1120, HDR + 1120 + 24, sealed.length - 1]) {
    assert.throws(() => openKey(kp.secretKey, sealed.subarray(0, n), keyId), `length ${n}`);
  }
  assert.throws(() => openKey(kp.secretKey, new Uint8Array([...sealed, 0]), keyId));
});

test('a symmetric record is not accepted as a sealed key and the reverse', () => {
  const kp = generateMailboxKeyPair();
  const sealed = sealKey(kp.publicKey, new Uint8Array(32), keyId);
  assert.throws(() => decrypt(key, sealed, keyId), /algorithm/);
  assert.throws(() => openKey(kp.secretKey, encrypt(key, msg, keyId), keyId), /algorithm/);
});
