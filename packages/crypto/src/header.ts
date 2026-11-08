// Every encrypted record starts with a small header: { version, algorithm, keyId }.
// It is also used as AEAD associated data, so it cannot be changed without detection.

export const VERSION = 1;

export const Algorithm = {
  /** XChaCha20-Poly1305 under a 32-byte symmetric key. */
  XChaCha20Poly1305: 1,
  /** X-Wing (ML-KEM-768 + X25519) key encapsulation, then XChaCha20-Poly1305. */
  XWingXChaCha20Poly1305: 2,
} as const;

export type Algorithm = (typeof Algorithm)[keyof typeof Algorithm];

export interface Header {
  version: number;
  algorithm: Algorithm;
  keyId: Uint8Array;
}

const KNOWN: ReadonlySet<number> = new Set(Object.values(Algorithm));

export function encodeHeader(h: Header): Uint8Array {
  if (h.keyId.length > 255) throw new Error('keyId too long (max 255 bytes)');
  const out = new Uint8Array(3 + h.keyId.length);
  out[0] = h.version;
  out[1] = h.algorithm;
  out[2] = h.keyId.length;
  out.set(h.keyId, 3);
  return out;
}

/** Parses a header at the start of `data`. Returns the header and its encoded length. */
export function decodeHeader(data: Uint8Array): { header: Header; length: number } {
  if (data.length < 3) throw new Error('record too short');
  const version = data[0]!;
  const algorithm = data[1]!;
  const idLen = data[2]!;
  if (version !== VERSION) throw new Error(`unsupported version ${version}`);
  if (!KNOWN.has(algorithm)) throw new Error(`unknown algorithm ${algorithm}`);
  if (data.length < 3 + idLen) throw new Error('record too short');
  return {
    header: { version, algorithm: algorithm as Algorithm, keyId: data.slice(3, 3 + idLen) },
    length: 3 + idLen,
  };
}
