import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  decrypt,
  generateRecoveryKey,
  generateUmk,
  recoveryKeyToSecret,
  unwrapUmk,
  wrapUmk,
} from './index.ts';
import type { UnlockKind } from './index.ts';

const utf8 = new TextEncoder();
const slot = utf8.encode('pw');
const user = utf8.encode('user-1');
const secret = new Uint8Array(64).fill(3); // same size as an OPAQUE export key
const secret32 = new Uint8Array(32).fill(3);

test('wrap and unwrap the UMK for every unlock kind', () => {
  const umk = generateUmk();
  assert.equal(umk.length, 32);
  for (const [kind, s] of [
    ['password', secret],
    ['passkey', secret32],
    ['recovery', secret32],
  ] as const) {
    assert.deepEqual(unwrapUmk(s, kind, wrapUmk(s, kind, umk, slot, user), slot, user), umk);
  }
});

test('unwrap rejects wrong secret, kind, slot, user and tampering', () => {
  const umk = generateUmk();
  const wrapped = wrapUmk(secret, 'password', umk, slot, user);
  assert.throws(() => unwrapUmk(new Uint8Array(64).fill(4), 'password', wrapped, slot, user));
  assert.throws(() => unwrapUmk(secret, 'password', wrapped, new Uint8Array([1]), user), /mism/);
  assert.throws(() => unwrapUmk(secret, 'password', wrapped, slot, utf8.encode('user-2')));
  assert.throws(() => unwrapUmk(secret, 'password', wrapped, slot, new Uint8Array()), /userId/);
  // same secret bytes, other kind: the KEK label differs
  const asPasskey = wrapUmk(secret32, 'passkey', umk, slot, user);
  assert.throws(() => unwrapUmk(secret32, 'recovery', asPasskey, slot, user));
  for (let i = 0; i < wrapped.length; i++) {
    const bad = wrapped.slice();
    bad[i] = bad[i]! ^ 1;
    assert.throws(() => unwrapUmk(secret, 'password', bad, slot, user), `byte ${i}`);
  }
});

test('wrap rejects wrong secret lengths, bad UMK length and unknown kinds', () => {
  const umk = generateUmk();
  for (const n of [0, 31, 32, 33, 63, 65]) {
    assert.throws(() => wrapUmk(new Uint8Array(n), 'password', umk, slot, user), /length/);
  }
  for (const n of [31, 33, 64]) {
    assert.throws(() => wrapUmk(new Uint8Array(n), 'passkey', umk, slot, user), /length/);
    assert.throws(() => wrapUmk(new Uint8Array(n), 'recovery', umk, slot, user), /length/);
  }
  assert.throws(() => wrapUmk(secret, 'password', new Uint8Array(31), slot, user), /32 bytes/);
  assert.throws(() => wrapUmk(secret, 'other' as UnlockKind, umk, slot, user), /unknown/);
  assert.throws(() => wrapUmk(secret, 'toString' as UnlockKind, umk, slot, user), /unknown/);
});

test('a wrapped UMK opens with a KEK derived outside the module (WebCrypto HKDF)', async () => {
  // Independent check: a change of label, hash or aad must break this test.
  const ikm = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  const info = utf8.encode('kindi/v1/kek/password');
  const params = { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info };
  const kek = await crypto.subtle.deriveBits(params, ikm, 256);
  const umk = generateUmk();
  const wrapped = wrapUmk(secret, 'password', umk, slot, user);
  const aad = utf8.encode('kindi/v1/umk-wrapuser-1');
  assert.deepEqual(decrypt(new Uint8Array(kek), wrapped, slot, aad), umk);
});

test('recovery key: 24 words, round trip, forgiving input, checksum', () => {
  const words = generateRecoveryKey();
  assert.equal(words.split(' ').length, 24);
  assert.notEqual(words, generateRecoveryKey());
  const s = recoveryKeyToSecret(words);
  assert.equal(s.length, 32);
  assert.deepEqual(recoveryKeyToSecret(`  ${words.toUpperCase().replaceAll(' ', ' \n ')} `), s);

  const umk = generateUmk();
  const wrapped = wrapUmk(s, 'recovery', umk, slot, user);
  assert.deepEqual(unwrapUmk(recoveryKeyToSecret(words), 'recovery', wrapped, slot, user), umk);

  const list = words.split(' ');
  assert.throws(() => recoveryKeyToSecret('abandon '.repeat(24))); // bad checksum
  assert.throws(() => recoveryKeyToSecret(list.slice(0, 12).join(' ')));
  assert.throws(() => recoveryKeyToSecret(''));
});

test('recovery key errors never contain what the user typed', () => {
  const typo = `${'abandon '.repeat(23)}sekretword`;
  assert.throws(
    () => recoveryKeyToSecret(typo),
    (e: Error) => e.message === 'invalid recovery key',
  );
});

test('recovery key matches the BIP39 reference vector', () => {
  // BIP39 test vector: 32 bytes of 0x00
  const words = `${'abandon '.repeat(23)}art`;
  assert.deepEqual(recoveryKeyToSecret(words), new Uint8Array(32));
});
