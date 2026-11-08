import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/ciphers/utils.js';
import { Algorithm, VERSION, decodeHeader, encodeHeader } from './header.ts';

const KEY_LEN = 32;
const NONCE_LEN = 24;

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Output: header || nonce(24) || ciphertext+tag. The header (and `aad`) are authenticated. */
export function encrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  keyId: Uint8Array,
  aad: Uint8Array = new Uint8Array(),
): Uint8Array {
  if (key.length !== KEY_LEN) throw new Error('key must be 32 bytes');
  const header = encodeHeader({ version: VERSION, algorithm: Algorithm.XChaCha20Poly1305, keyId });
  const nonce = randomBytes(NONCE_LEN);
  const ct = xchacha20poly1305(key, nonce, concat(header, aad)).encrypt(plaintext);
  return concat(header, nonce, ct);
}

/** `expectedKeyId` is the key the caller meant to use. The header keyId is only a hint until this check. */
export function decrypt(
  key: Uint8Array,
  record: Uint8Array,
  expectedKeyId: Uint8Array,
  aad: Uint8Array = new Uint8Array(),
): Uint8Array {
  if (key.length !== KEY_LEN) throw new Error('key must be 32 bytes');
  const { header, length } = decodeHeader(record);
  if (header.algorithm !== Algorithm.XChaCha20Poly1305) throw new Error('wrong algorithm');
  if (!sameBytes(header.keyId, expectedKeyId)) throw new Error('key id mismatch');
  const nonce = record.subarray(length, length + NONCE_LEN);
  const ct = record.subarray(length + NONCE_LEN);
  if (nonce.length !== NONCE_LEN) throw new Error('record too short');
  return xchacha20poly1305(key, nonce, concat(record.subarray(0, length), aad)).decrypt(ct);
}

// keyId is not secret, so a plain comparison is fine.
function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

export { concat, sameBytes };
