import { randomBytes } from '@noble/ciphers/utils.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { entropyToMnemonic, mnemonicToEntropy } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { decrypt, encrypt } from './aead.ts';

// The user master key (UMK) is random and never leaves the client in the clear.
// It is stored only wrapped, once per unlock path. Each path has its own secret:
//   password: OPAQUE export key, passkey: WebAuthn PRF output, recovery: recovery key entropy.

const UMK_LEN = 32;
const utf8 = new TextEncoder();
const WRAP_LABEL = utf8.encode('kindi/v1/umk-wrap');

export type UnlockKind = 'password' | 'passkey' | 'recovery';
// Exact secret length per kind. HKDF does no stretching, so the secret must already be
// high entropy. The fixed sizes keep a raw password or a wrong value out by accident.
const SECRET_LEN: Record<UnlockKind, number> = {
  password: 64, // OPAQUE export key
  passkey: 32, // WebAuthn PRF output
  recovery: 32, // recoveryKeyToSecret()
};

export function generateUmk(): Uint8Array {
  return randomBytes(UMK_LEN);
}

function kek(secret: Uint8Array, kind: UnlockKind): Uint8Array {
  if (!Object.hasOwn(SECRET_LEN, kind)) throw new Error('unknown unlock kind');
  if (secret.length !== SECRET_LEN[kind]) throw new Error('unlock secret has wrong length');
  return hkdf(sha256, secret, undefined, utf8.encode(`kindi/v1/kek/${kind}`), 32);
}

// The label is fixed length, so label || userId cannot be read two ways.
function wrapAad(userId: Uint8Array): Uint8Array {
  if (userId.length === 0) throw new Error('userId is required');
  const aad = new Uint8Array(WRAP_LABEL.length + userId.length);
  aad.set(WRAP_LABEL);
  aad.set(userId, WRAP_LABEL.length);
  return aad;
}

/**
 * Wraps the UMK for one unlock path. `keyId` names the slot (for example one passkey).
 * The record is bound to `userId`. The key-encryption key is derived here and wiped
 * before returning.
 *
 * Changing a password re-wraps the same UMK. It does NOT lock out someone who already
 * has an old wrapped copy and the old secret; that needs a UMK rotation.
 */
export function wrapUmk(
  secret: Uint8Array,
  kind: UnlockKind,
  umk: Uint8Array,
  keyId: Uint8Array,
  userId: Uint8Array,
): Uint8Array {
  if (umk.length !== UMK_LEN) throw new Error('umk must be 32 bytes');
  const aad = wrapAad(userId);
  const key = kek(secret, kind);
  try {
    return encrypt(key, umk, keyId, aad);
  } finally {
    key.fill(0);
  }
}

/**
 * Throws if the secret, the kind, the slot or the user is wrong, or if the record was changed.
 * `expectedKeyId` and `userId` must come from what the client knows, not from the stored record.
 * The caller should zero the returned UMK after use.
 */
export function unwrapUmk(
  secret: Uint8Array,
  kind: UnlockKind,
  wrapped: Uint8Array,
  expectedKeyId: Uint8Array,
  userId: Uint8Array,
): Uint8Array {
  const aad = wrapAad(userId);
  const key = kek(secret, kind);
  try {
    const umk = decrypt(key, wrapped, expectedKeyId, aad);
    if (umk.length !== UMK_LEN) {
      umk.fill(0);
      throw new Error('wrapped umk has wrong length');
    }
    return umk;
  } finally {
    key.fill(0);
  }
}

/**
 * Derives a 32-byte key from the UMK for one purpose (for example "contacts" or
 * "mailbox-key"). The UMK itself is never used to encrypt data: every use gets its own
 * subkey, so a leaked subkey does not expose the UMK or the other subkeys.
 * The caller should zero the result after use.
 */
export function deriveSubkey(umk: Uint8Array, purpose: string): Uint8Array {
  if (umk.length !== UMK_LEN) throw new Error('umk must be 32 bytes');
  // A strict format keeps the HKDF label unambiguous and stable across clients.
  // The typeof check matters: RegExp.test would turn undefined into the purpose "undefined".
  if (typeof purpose !== 'string' || !/^[a-z0-9-]{1,64}$/.test(purpose)) {
    throw new Error('invalid subkey purpose');
  }
  return hkdf(sha256, umk, undefined, utf8.encode(`kindi/v1/subkey/${purpose}`), 32);
}

/** A new recovery key: 24 words (256 bits + checksum, BIP39 English list). Show it once. */
export function generateRecoveryKey(): string {
  const entropy = randomBytes(32);
  try {
    return entropyToMnemonic(entropy, wordlist);
  } finally {
    entropy.fill(0);
  }
}

/**
 * Turns the typed recovery key into the unlock secret for kind 'recovery'.
 * Case and extra spaces are ignored. Throws on an unknown word, a bad checksum
 * or anything other than 24 words. The caller should zero the result after use.
 */
export function recoveryKeyToSecret(words: string): Uint8Array {
  let secret: Uint8Array | undefined;
  try {
    secret = mnemonicToEntropy(words.trim().toLowerCase().split(/\s+/).join(' '), wordlist);
  } catch {
    // The library error contains the mistyped word. Never pass it on.
  }
  if (secret?.length !== 32) throw new Error('invalid recovery key');
  return secret;
}
