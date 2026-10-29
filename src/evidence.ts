import {
  bytesEqual,
  hmac,
  hmacKeyRepresentations,
  jwkToPublicKey,
  rsaModulusBits,
  verifySignature,
  type KeyRepresentation,
  type LoadedKey,
} from './crypto.js';
import { WEAK_SECRETS } from './data/weak-secrets.js';
import type { DecodedToken } from './decode.js';
import type { AlgorithmInfo, VerificationResult } from './types.js';

export interface RecoveredSecret {
  readonly secret: string;
  readonly origin: string;
}

export interface ConfusionHit {
  readonly keySource: string;
  readonly representation: KeyRepresentation;
}

export interface ConfusionCandidate {
  readonly keySource: string;
  readonly representations: number;
}

export interface EmbeddedJwkEvidence {
  readonly usable: boolean;
  readonly keyType: string | null;
  readonly selfConsistent: boolean;
  readonly error: string | null;
}

/**
 * Everything the analyser established by actually doing cryptography, gathered
 * before any rule runs so that rules stay declarative and every claim of the
 * form "this was verified" has exactly one place it can come from.
 */
export interface CryptoEvidence {
  readonly verification: readonly VerificationResult[];
  readonly recoveredSecret: RecoveredSecret | null;
  readonly confusion: ConfusionHit | null;
  readonly confusionCandidate: ConfusionCandidate | null;
  readonly embeddedJwk: EmbeddedJwkEvidence | null;
  readonly ecdsaZeroSignature: boolean;
  readonly rsaKeyBits: number | null;
  readonly secretsTried: number;
  readonly notes: readonly string[];
}

export interface EvidenceInputs {
  readonly keys: readonly LoadedKey[];
  readonly hmacSecret: string | null;
  readonly extraSecrets: readonly string[];
}

function allZero(bytes: Uint8Array): boolean {
  if (bytes.length === 0) return false;
  for (const byte of bytes) if (byte !== 0) return false;
  return true;
}

function candidateSecrets(inputs: EvidenceInputs): { secret: string; origin: string }[] {
  const seen = new Set<string>();
  const out: { secret: string; origin: string }[] = [];
  const add = (secret: string, origin: string): void => {
    if (seen.has(secret)) return;
    seen.add(secret);
    out.push({ secret, origin });
  };
  if (inputs.hmacSecret !== null) add(inputs.hmacSecret, 'supplied with --hmac-secret');
  for (const secret of inputs.extraSecrets) add(secret, 'supplied with --secret-list');
  for (const secret of WEAK_SECRETS) add(secret, 'built-in list of common defaults');
  return out;
}

export function gatherEvidence(
  token: DecodedToken,
  algorithm: AlgorithmInfo,
  inputs: EvidenceInputs,
): CryptoEvidence {
  const verification: VerificationResult[] = [];
  const notes: string[] = [];

  let recoveredSecret: RecoveredSecret | null = null;
  let confusion: ConfusionHit | null = null;
  let confusionCandidate: ConfusionCandidate | null = null;
  let rsaKeyBits: number | null = null;

  const symmetric = algorithm.family === 'hmac';
  const asymmetric =
    algorithm.family === 'rsa' ||
    algorithm.family === 'rsa-pss' ||
    algorithm.family === 'ecdsa' ||
    algorithm.family === 'eddsa';

  const secrets = candidateSecrets(inputs);

  if (symmetric && token.signature.length > 0) {
    for (const candidate of secrets) {
      const computed = hmac(algorithm, Buffer.from(candidate.secret, 'utf8'), token.signingInput);
      if (!bytesEqual(computed, token.signature)) continue;
      recoveredSecret = { secret: candidate.secret, origin: candidate.origin };
      verification.push({
        source: candidate.origin,
        valid: true,
        detail: `${algorithm.declared} with the secret ${candidate.secret === '' ? '(the empty string)' : JSON.stringify(candidate.secret)}`,
      });
      break;
    }
    if (recoveredSecret === null && inputs.hmacSecret !== null) {
      verification.push({
        source: 'supplied with --hmac-secret',
        valid: false,
        detail: `${algorithm.declared} with the supplied secret does not reproduce this signature`,
      });
    }
  } else if (symmetric) {
    notes.push('The signature segment is empty, so there is no MAC to test a secret against.');
  }

  for (const key of inputs.keys) {
    if (key.derivedFromPrivate) {
      notes.push(`${key.source}: a private key was supplied; its public part was derived and used.`);
    }
    if (asymmetric) {
      const valid = verifySignature(algorithm, key.keyObject, token.signingInput, token.signature);
      // Only a key that actually verifies the token tells us anything about the
      // key the token was signed with, so only that key's size is reported as
      // measured rather than inferred.
      if (valid && rsaKeyBits === null && key.keyObject.asymmetricKeyType === 'rsa') {
        rsaKeyBits = rsaModulusBits(key.keyObject);
      }
      verification.push({
        source: key.source,
        valid,
        detail: valid
          ? `${algorithm.declared} verifies under this key`
          : `${algorithm.declared} does not verify under this key`,
      });
    }

    if (symmetric && confusion === null) {
      // The declared algorithm is symmetric and we hold an asymmetric public
      // key. If the MAC matches any byte representation of that key, the token
      // is an algorithm-confusion forgery and we can say so without hedging.
      for (const representation of hmacKeyRepresentations(key)) {
        const computed = hmac(algorithm, representation.bytes, token.signingInput);
        if (!bytesEqual(computed, token.signature)) continue;
        confusion = { keySource: key.source, representation };
        verification.push({
          source: `${key.source} (as an HMAC secret, ${representation.label})`,
          valid: true,
          detail: `${algorithm.declared} over the signing input with ${representation.description}`,
        });
        break;
      }
    }

    if (asymmetric && confusionCandidate === null) {
      confusionCandidate = {
        keySource: key.source,
        representations: hmacKeyRepresentations(key).length,
      };
    }
  }

  if (symmetric && inputs.keys.length > 0 && confusion === null) {
    notes.push(
      'A public key was supplied and the token declares an HMAC algorithm, but no byte representation of that key reproduces the signature. The token was not forged with this key; that says nothing about whether the verifier would accept one that was.',
    );
  }

  let embeddedJwk: EmbeddedJwkEvidence | null = null;
  if (token.header['jwk'] !== undefined) {
    try {
      const keyObject = jwkToPublicKey(token.header['jwk']);
      const selfConsistent = asymmetric
        ? verifySignature(algorithm, keyObject, token.signingInput, token.signature)
        : false;
      if (!asymmetric) {
        notes.push(
          'The header embeds a `jwk` but declares a symmetric algorithm, so the embedded key cannot be used to check the signature.',
        );
      }
      embeddedJwk = {
        usable: true,
        keyType: keyObject.asymmetricKeyType ?? null,
        selfConsistent,
        error: null,
      };
      if (selfConsistent) {
        verification.push({
          source: 'the `jwk` embedded in the token header',
          valid: true,
          detail: `${algorithm.declared} verifies under the token's own embedded key`,
        });
      }
    } catch (error) {
      embeddedJwk = {
        usable: false,
        keyType: null,
        selfConsistent: false,
        error: (error as Error).message,
      };
    }
  }

  const ecdsaZeroSignature = algorithm.family === 'ecdsa' && allZero(token.signature);

  return {
    verification,
    recoveredSecret,
    confusion,
    confusionCandidate,
    embeddedJwk,
    ecdsaZeroSignature,
    rsaKeyBits,
    secretsTried: symmetric && token.signature.length > 0 ? secrets.length : 0,
    notes,
  };
}
