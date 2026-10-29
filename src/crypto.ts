import {
  constants,
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  timingSafeEqual,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';

import type { AlgorithmInfo } from './types.js';

/**
 * Every cryptographic primitive this tool uses comes from `node:crypto`.
 * Nothing here implements RSA, ECDSA, SHA-2 or HMAC; this module is only
 * concerned with feeding Node the right parameters, which for JOSE is the part
 * that is easy to get wrong:
 *
 *  - A JWS ECDSA signature is the raw `r || s` concatenation of RFC 7518 §3.4.
 *    Node defaults to DER, so `dsaEncoding: 'ieee-p1363'` is mandatory. Omit it
 *    and every ES256 verification fails for the wrong reason.
 *  - RSA-PSS needs the salt length pinned to the digest length, which is what
 *    RFC 7518 §3.5 specifies and not what Node defaults to.
 *  - EdDSA takes a `null` algorithm, because Ed25519 fixes its own digest.
 */

export interface LoadedKey {
  /** Human-readable provenance, used verbatim in output. */
  readonly source: string;
  readonly keyObject: KeyObject;
  /** The exact bytes of the file this key was read from, when it came from a file. */
  readonly fileBytes: Buffer | null;
  readonly jwk: Readonly<Record<string, unknown>> | null;
  /** Whether a private key was supplied and the public part derived from it. */
  readonly derivedFromPrivate: boolean;
}

export interface KeyRepresentation {
  readonly label: string;
  readonly description: string;
  readonly bytes: Buffer;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  if (a.length === 0) return true;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function nodeDigest(algorithm: AlgorithmInfo): string {
  switch (algorithm.hash) {
    case 'sha256':
      return 'sha256';
    case 'sha384':
      return 'sha384';
    case 'sha512':
      return 'sha512';
    default:
      throw new Error(`algorithm ${algorithm.declared} has no associated digest`);
  }
}

function saltLength(algorithm: AlgorithmInfo): number {
  switch (algorithm.hash) {
    case 'sha256':
      return 32;
    case 'sha384':
      return 48;
    case 'sha512':
      return 64;
    default:
      throw new Error(`algorithm ${algorithm.declared} has no associated digest`);
  }
}

export function hmac(algorithm: AlgorithmInfo, key: Uint8Array | string, signingInput: string): Buffer {
  return createHmac(nodeDigest(algorithm), key as Buffer | string)
    .update(signingInput, 'utf8')
    .digest();
}

/** Sign `signingInput` with a private key, producing a JWS-shaped signature. */
export function signAsymmetric(
  algorithm: AlgorithmInfo,
  privateKey: KeyObject,
  signingInput: string,
): Buffer {
  const data = Buffer.from(signingInput, 'utf8');
  switch (algorithm.family) {
    case 'rsa':
      return cryptoSign(nodeDigest(algorithm), data, privateKey);
    case 'rsa-pss':
      return cryptoSign(nodeDigest(algorithm), data, {
        key: privateKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: saltLength(algorithm),
      });
    case 'ecdsa':
      return cryptoSign(nodeDigest(algorithm), data, {
        key: privateKey,
        dsaEncoding: 'ieee-p1363',
      });
    case 'eddsa':
      return cryptoSign(null, data, privateKey);
    default:
      throw new Error(`${algorithm.declared} is not an asymmetric signing algorithm`);
  }
}

/**
 * Verify a JWS signature. Returns `false` rather than throwing on any failure,
 * including a key of the wrong type for the algorithm, because "this key does
 * not verify this token" is the answer in every one of those cases.
 */
export function verifySignature(
  algorithm: AlgorithmInfo,
  keyObject: KeyObject,
  signingInput: string,
  signature: Uint8Array,
): boolean {
  const data = Buffer.from(signingInput, 'utf8');
  try {
    switch (algorithm.family) {
      case 'rsa':
        return cryptoVerify(nodeDigest(algorithm), data, keyObject, signature);
      case 'rsa-pss':
        return cryptoVerify(
          nodeDigest(algorithm),
          data,
          {
            key: keyObject,
            padding: constants.RSA_PKCS1_PSS_PADDING,
            saltLength: saltLength(algorithm),
          },
          signature,
        );
      case 'ecdsa':
        return cryptoVerify(
          nodeDigest(algorithm),
          data,
          { key: keyObject, dsaEncoding: 'ieee-p1363' },
          signature,
        );
      case 'eddsa':
        return cryptoVerify(null, data, keyObject, signature);
      default:
        return false;
    }
  } catch {
    return false;
  }
}

/** Load a public key from PEM text, a bare JWK, or a JWKS document. */
export function loadKeysFromText(text: string, source: string, fileBytes: Buffer | null): LoadedKey[] {
  const trimmed = text.trim();

  if (trimmed.startsWith('{')) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch (error) {
      throw new Error(`${source}: not valid JSON (${(error as Error).message})`);
    }
    const record = parsed as Record<string, unknown>;
    const keys = Array.isArray(record['keys']) ? (record['keys'] as unknown[]) : [record];
    const loaded: LoadedKey[] = [];
    keys.forEach((entry, index) => {
      if (entry === null || typeof entry !== 'object') return;
      const jwk = entry as Record<string, unknown>;
      const kid = typeof jwk['kid'] === 'string' ? jwk['kid'] : null;
      const label = kid === null ? `${source}[${index}]` : `${source}[kid=${kid}]`;
      try {
        loaded.push({
          source: label,
          keyObject: createPublicKey({ key: jwk as never, format: 'jwk' }),
          fileBytes: null,
          jwk,
          derivedFromPrivate: false,
        });
      } catch (error) {
        throw new Error(`${label}: not a usable JWK (${(error as Error).message})`);
      }
    });
    if (loaded.length === 0) throw new Error(`${source}: no usable keys in the document`);
    return loaded;
  }

  // PEM. `createPublicKey` will happily take a private key and hand back the
  // public half, which is a convenience worth keeping — the only copy of a key
  // a tester has is often the signing key from a staging environment. It is
  // also worth saying out loud, so the private case is detected separately and
  // surfaced as a note rather than passing silently.
  let derivedFromPrivate = false;
  try {
    createPrivateKey(trimmed);
    derivedFromPrivate = true;
  } catch {
    // Not a private key, which is the expected case.
  }

  try {
    return [
      {
        source,
        keyObject: createPublicKey(trimmed),
        fileBytes,
        jwk: null,
        derivedFromPrivate,
      },
    ];
  } catch (error) {
    throw new Error(`${source}: not a PEM key or JWK document (${(error as Error).message})`);
  }
}

/**
 * Every byte string a verifier might plausibly hand to its HMAC function when
 * it has been tricked into treating an asymmetric public key as a shared
 * secret.
 *
 * This is the crux of the HS/RS confusion check and the reason it is worth
 * doing properly. The attack is not "use the public key"; it is "use the exact
 * bytes the target's code passes to its HMAC function". Those bytes depend on
 * how the application holds the key:
 *
 *  - `fs.readFileSync('key.pem')` gives the file verbatim, trailing newline and
 *    all. This is the common case and the one most often missed, because a
 *    PEM re-exported by a crypto library will not be byte-identical to the file
 *    on disk — different line wrapping, a different trailing newline.
 *  - A key round-tripped through a library arrives as a normalised SPKI or
 *    PKCS#1 PEM.
 *  - Some code paths pass DER, or base64 of DER, or an RSA modulus pulled out
 *    of a JWK.
 *
 * Getting one of these wrong produces a MAC that does not match and a tester
 * who concludes the target is not vulnerable. So the analyser tries all of
 * them and reports which one matched.
 */
export function hmacKeyRepresentations(key: LoadedKey): KeyRepresentation[] {
  const out: KeyRepresentation[] = [];
  const push = (label: string, description: string, bytes: Buffer | null): void => {
    if (bytes === null || bytes.length === 0) return;
    if (out.some((existing) => existing.bytes.equals(bytes))) return;
    out.push({ label, description, bytes });
  };

  if (key.fileBytes !== null) {
    push('file-bytes', 'the key file read verbatim, including any trailing newline', key.fileBytes);
    const trimmedTail = Buffer.from(key.fileBytes.toString('utf8').replace(/\s+$/, ''), 'utf8');
    push('file-bytes-trimmed', 'the key file with trailing whitespace stripped', trimmedTail);
  }

  const tryExport = (fn: () => Buffer | string): Buffer | null => {
    try {
      const result = fn();
      return typeof result === 'string' ? Buffer.from(result, 'utf8') : result;
    } catch {
      return null;
    }
  };

  const spkiPem = tryExport(() => key.keyObject.export({ type: 'spki', format: 'pem' }));
  push('spki-pem', 'SPKI PEM as a crypto library would re-export it', spkiPem);
  if (spkiPem !== null) {
    push(
      'spki-pem-no-trailing-newline',
      'SPKI PEM with the trailing newline removed',
      Buffer.from(spkiPem.toString('utf8').replace(/\n+$/, ''), 'utf8'),
    );
  }

  if (key.keyObject.asymmetricKeyType === 'rsa') {
    const pkcs1Pem = tryExport(() => key.keyObject.export({ type: 'pkcs1', format: 'pem' }));
    push('pkcs1-pem', 'PKCS#1 RSA PUBLIC KEY PEM', pkcs1Pem);
    if (pkcs1Pem !== null) {
      push(
        'pkcs1-pem-no-trailing-newline',
        'PKCS#1 PEM with the trailing newline removed',
        Buffer.from(pkcs1Pem.toString('utf8').replace(/\n+$/, ''), 'utf8'),
      );
    }
  }

  const spkiDer = tryExport(() => key.keyObject.export({ type: 'spki', format: 'der' }));
  push('spki-der', 'raw SPKI DER bytes', spkiDer);
  if (spkiDer !== null) {
    push('spki-der-base64', 'base64 of the SPKI DER bytes', Buffer.from(spkiDer.toString('base64'), 'utf8'));
  }

  try {
    const jwk = key.keyObject.export({ format: 'jwk' }) as Record<string, unknown>;
    if (typeof jwk['n'] === 'string') {
      push('jwk-modulus', 'the base64url RSA modulus `n` from the key as a JWK', Buffer.from(jwk['n'], 'utf8'));
    }
    if (typeof jwk['x'] === 'string') {
      push('jwk-x', 'the base64url `x` coordinate from the key as a JWK', Buffer.from(jwk['x'], 'utf8'));
    }
  } catch {
    // Nothing to add; the export is best-effort.
  }

  return out;
}

export function jwkToPublicKey(jwk: unknown): KeyObject {
  if (jwk === null || typeof jwk !== 'object' || Array.isArray(jwk)) {
    throw new Error('embedded `jwk` header is not a JSON object');
  }
  return createPublicKey({ key: jwk as never, format: 'jwk' });
}

export function publicKeyToJwk(keyObject: KeyObject): Record<string, unknown> {
  return keyObject.export({ format: 'jwk' }) as Record<string, unknown>;
}

export function rsaModulusBits(keyObject: KeyObject): number | null {
  const size = keyObject.asymmetricKeyDetails?.modulusLength;
  return typeof size === 'number' ? size : null;
}

export function generateRsaKeyPair(modulusLength = 2048): { publicKey: KeyObject; privateKey: KeyObject } {
  return generateKeyPairSync('rsa', { modulusLength });
}
