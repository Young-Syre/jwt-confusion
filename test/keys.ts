import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto';

import { encodeBase64url, encodeJsonBase64url } from '../src/base64url.js';

/**
 * Test key material, and the reason none of it is committed.
 *
 * A PEM-wrapped private key is one of the literals GitHub push protection
 * blocks, so a repository that ships an RSA test key cannot be pushed. Rather
 * than work around the protection, this file builds its keys at test time:
 *
 *  - Ed25519 is derived deterministically from the seed below. An Ed25519
 *    PKCS#8 document is a fixed 16-byte prefix followed by the 32-byte seed,
 *    so a committed hex seed reproduces the identical keypair on every run and
 *    on every machine, with no PEM anywhere.
 *  - RSA and EC cannot be seeded through `node:crypto`, and deriving them from
 *    a seed would mean implementing prime generation, which is exactly the kind
 *    of hand-rolled cryptography this project refuses to do. They are generated
 *    per test process instead and cached, so the cost is paid once. Nothing in
 *    the suite depends on a specific RSA key, only on having one.
 */
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** Fabricated. Not a key from anywhere, and public in every sense. */
export const TEST_ED25519_SEED_HEX =
  '4a57542d636f6e667573696f6e2d746573742d736565642d30303030303031';

export interface Pair {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
}

export function deterministicEd25519(seedHex: string = TEST_ED25519_SEED_HEX): Pair {
  const seed = Buffer.from(seedHex.padEnd(64, '0').slice(0, 64), 'hex');
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

let cachedRsa: Pair | null = null;
export function rsaPair(): Pair {
  cachedRsa ??= generateKeyPairSync('rsa', { modulusLength: 2048 });
  return cachedRsa;
}

let cachedEc: Pair | null = null;
export function ecPair(): Pair {
  cachedEc ??= generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return cachedEc;
}

export function spkiPem(key: KeyObject): string {
  return key.export({ type: 'spki', format: 'pem' }) as string;
}

/** Assemble a compact JWS from parts, with no signing. */
export function makeToken(
  header: Record<string, unknown>,
  payload: Record<string, unknown> | string,
  signature: Uint8Array | string = '',
): string {
  const headerSegment = encodeJsonBase64url(header);
  const payloadSegment = typeof payload === 'string' ? encodeBase64url(payload) : encodeJsonBase64url(payload);
  const signatureSegment = typeof signature === 'string' ? signature : encodeBase64url(signature);
  return `${headerSegment}.${payloadSegment}.${signatureSegment}`;
}

/** A payload with every registered claim present and a short lifetime. */
export function wellFormedClaims(now = 1760000000): Record<string, unknown> {
  return {
    iss: 'https://issuer.example',
    sub: 'user-1042',
    aud: 'https://api.example',
    exp: now + 600,
    nbf: now,
    iat: now,
    jti: 'bb4f0f6c-1e0f-4a1a-9f4e-000000000001',
  };
}
