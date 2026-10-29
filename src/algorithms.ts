import type { AlgorithmFamily, AlgorithmInfo } from './types.js';

interface AlgorithmSpec {
  readonly family: AlgorithmFamily;
  readonly hash: 'sha256' | 'sha384' | 'sha512' | null;
  readonly signatureBytes: number | null;
}

/**
 * The JWS algorithms this tool recognises. `signatureBytes` is `null` for RSA
 * because an RSA signature is exactly as long as the modulus, which the token
 * does not carry.
 *
 * ECDSA lengths are the raw `r || s` concatenation of RFC 7518 §3.4, not DER.
 * ES512 is 132 and not 128 because P-521's field elements are 66 bytes each.
 */
const REGISTRY: Readonly<Record<string, AlgorithmSpec>> = {
  HS256: { family: 'hmac', hash: 'sha256', signatureBytes: 32 },
  HS384: { family: 'hmac', hash: 'sha384', signatureBytes: 48 },
  HS512: { family: 'hmac', hash: 'sha512', signatureBytes: 64 },
  RS256: { family: 'rsa', hash: 'sha256', signatureBytes: null },
  RS384: { family: 'rsa', hash: 'sha384', signatureBytes: null },
  RS512: { family: 'rsa', hash: 'sha512', signatureBytes: null },
  PS256: { family: 'rsa-pss', hash: 'sha256', signatureBytes: null },
  PS384: { family: 'rsa-pss', hash: 'sha384', signatureBytes: null },
  PS512: { family: 'rsa-pss', hash: 'sha512', signatureBytes: null },
  ES256: { family: 'ecdsa', hash: 'sha256', signatureBytes: 64 },
  ES256K: { family: 'ecdsa', hash: 'sha256', signatureBytes: 64 },
  ES384: { family: 'ecdsa', hash: 'sha384', signatureBytes: 96 },
  ES512: { family: 'ecdsa', hash: 'sha512', signatureBytes: 132 },
  EdDSA: { family: 'eddsa', hash: null, signatureBytes: 64 },
  none: { family: 'none', hash: null, signatureBytes: 0 },
};

export const REGISTERED_ALGORITHMS: readonly string[] = Object.keys(REGISTRY);

/** Plausible RSA modulus sizes in bytes, i.e. 1024/2048/3072/4096-bit keys. */
export const RSA_SIGNATURE_LENGTHS: readonly number[] = [128, 256, 384, 512];

function findCaseVariant(declared: string): string | null {
  const lowered = declared.toLowerCase();
  for (const name of REGISTERED_ALGORITHMS) {
    if (name !== declared && name.toLowerCase() === lowered) return name;
  }
  return null;
}

export function describeAlgorithm(declared: unknown): AlgorithmInfo {
  if (typeof declared !== 'string') {
    return {
      declared: declared === undefined ? '' : String(JSON.stringify(declared)),
      family: 'unknown',
      hash: null,
      signatureBytes: null,
      registered: false,
      caseVariantOf: null,
    };
  }

  const exact = Object.prototype.hasOwnProperty.call(REGISTRY, declared) ? REGISTRY[declared] : undefined;
  if (exact) {
    return {
      declared,
      family: exact.family,
      hash: exact.hash,
      signatureBytes: exact.signatureBytes,
      registered: true,
      caseVariantOf: null,
    };
  }

  const variant = findCaseVariant(declared);
  if (variant) {
    const spec = REGISTRY[variant] as AlgorithmSpec;
    return {
      declared,
      // A case variant is treated as belonging to the family a lenient verifier
      // would dispatch it to, so that signature-length expectations still apply.
      family: spec.family,
      hash: spec.hash,
      signatureBytes: spec.signatureBytes,
      registered: false,
      caseVariantOf: variant,
    };
  }

  return {
    declared,
    family: 'unknown',
    hash: null,
    signatureBytes: null,
    registered: false,
    caseVariantOf: null,
  };
}

export function isNoneVariant(algorithm: AlgorithmInfo): boolean {
  return algorithm.family === 'none' && algorithm.declared !== 'none';
}
