import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/ciphers/utils.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js';
import { concat, sameBytes } from './aead.ts';
import { Algorithm, VERSION, decodeHeader, encodeHeader } from './header.ts';

const CEK_LEN = 32;
const NONCE_LEN = 24;
const CT_LEN = 1120; // ML-KEM-768 ciphertext (1088) + X25519 point (32); checked in tests
const PK_LEN = 1216; // ML-KEM-768 public key (1184) + X25519 point (32); checked in tests
const SK_LEN = 32; // X-Wing secret key is a seed
const LABEL = new TextEncoder().encode('kindi/v1/seal-cek');

export interface MailboxKeyPair {
  publicKey: Uint8Array;
  /** X-Wing secret key (a 32-byte seed). Store it only encrypted; never log or serialize it. */
  secretKey: Uint8Array;
}

export function generateMailboxKeyPair(): MailboxKeyPair {
  return xwing.keygen();
}

// The raw KEM secret is never used as a key: it goes through HKDF with a label and the header.
function aeadKey(sharedSecret: Uint8Array, header: Uint8Array): Uint8Array {
  return hkdf(sha256, sharedSecret, undefined, concat(LABEL, header), 32);
}

/**
 * Seals a content key (CEK) to the mailbox public key.
 * Output: header || kemCiphertext || nonce(24) || AEAD(cek).
 * Header and kemCiphertext are authenticated.
 *
 * This gives confidentiality only. Anyone who has the public key can seal a key,
 * so a successful open does NOT prove who sent it. Sender authenticity needs a
 * separate signature layer.
 */
export function sealKey(publicKey: Uint8Array, cek: Uint8Array, keyId: Uint8Array): Uint8Array {
  if (publicKey.length !== PK_LEN) throw new Error('public key has wrong length');
  if (cek.length !== CEK_LEN) throw new Error('cek must be 32 bytes');
  const header = encodeHeader({
    version: VERSION,
    algorithm: Algorithm.XWingXChaCha20Poly1305,
    keyId,
  });
  const { cipherText, sharedSecret } = xwing.encapsulate(publicKey);
  const key = aeadKey(sharedSecret, header);
  try {
    const nonce = randomBytes(NONCE_LEN);
    const ct = xchacha20poly1305(key, nonce, concat(header, cipherText)).encrypt(cek);
    return concat(header, cipherText, nonce, ct);
  } finally {
    sharedSecret.fill(0);
    key.fill(0);
  }
}

/** `expectedKeyId` is the key the caller meant to use. The header keyId is only a hint until this check. */
export function openKey(
  secretKey: Uint8Array,
  sealed: Uint8Array,
  expectedKeyId: Uint8Array,
): Uint8Array {
  if (secretKey.length !== SK_LEN) throw new Error('secret key has wrong length');
  const { header, length } = decodeHeader(sealed);
  if (header.algorithm !== Algorithm.XWingXChaCha20Poly1305) throw new Error('wrong algorithm');
  if (!sameBytes(header.keyId, expectedKeyId)) throw new Error('key id mismatch');
  const kemCt = sealed.subarray(length, length + CT_LEN);
  const nonce = sealed.subarray(length + CT_LEN, length + CT_LEN + NONCE_LEN);
  const ct = sealed.subarray(length + CT_LEN + NONCE_LEN);
  if (kemCt.length !== CT_LEN || nonce.length !== NONCE_LEN) throw new Error('record too short');
  const headerBytes = sealed.subarray(0, length);
  const sharedSecret = xwing.decapsulate(kemCt, secretKey);
  const key = aeadKey(sharedSecret, headerBytes);
  try {
    return xchacha20poly1305(key, nonce, concat(headerBytes, kemCt)).decrypt(ct);
  } finally {
    sharedSecret.fill(0);
    key.fill(0);
  }
}
