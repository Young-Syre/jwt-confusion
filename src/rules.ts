import { describeAlgorithm, isNoneVariant, RSA_SIGNATURE_LENGTHS } from './algorithms.js';
import type { CryptoEvidence } from './evidence.js';
import type { DecodedToken } from './decode.js';
import type { AlgorithmInfo, Finding } from './types.js';

export interface RuleContext {
  readonly token: DecodedToken;
  readonly algorithm: AlgorithmInfo;
  readonly evidence: CryptoEvidence;
  readonly now: Date;
  readonly expectAlg: string | null;
  readonly maxLifetimeSeconds: number;
  readonly secretListSize: number;
}

export interface Rule {
  readonly id: string;
  readonly name: string;
  readonly apply: (context: RuleContext) => Finding | Finding[] | null;
}

function headerString(context: RuleContext, name: string): string | null {
  const value = context.token.header[name];
  return typeof value === 'string' ? value : null;
}

function claimNumber(context: RuleContext, name: string): number | null {
  const value = context.token.payload?.[name];
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).host || null;
  } catch {
    return null;
  }
}

const URL_SHAPED = /^[a-z][a-z0-9+.\-]*:\/\//i;
const TRAVERSAL = /(^|[/\\])\.\.([/\\]|$)|%2e%2e|%00|\0/i;
const PATH_SHAPED = /^[/\\]|[/\\]|\.(pem|key|crt|der|json|txt)$/i;

/**
 * A `kid` with its percent-encoded path separators decoded, once.
 *
 * Both patterns above require a *literal* `/` or `\`. A verifier that uses
 * `kid` to locate a key file generally decodes it first, so
 * `..%2fetc%2fpasswd` is the same attack as `../etc/passwd` -- and it matched
 * neither pattern, so it produced no `kid` finding at all. Neither did
 * `..%5c..%5cwindows`. The `%2e%2e` clause covered the mirror-image case
 * where the dots are encoded and the slash is literal, which is how the gap
 * stayed hidden: one encoding of the pair was handled and the other was not.
 *
 * Only the separators, the dot and the NUL are decoded, not the whole value.
 * `decodeURIComponent` would throw on a malformed escape -- `kid` is attacker
 * input and a lone `%` is a legal thing for it to contain -- and would also
 * rewrite characters the SQL and URL rules read literally.
 *
 * One pass, deliberately: `..%252f` decodes to `..%2f`, not to `../`, and a
 * verifier that double-decodes is a different bug from the one this reports.
 */
function decodePathEscapes(value: string): string {
  return value
    .replace(/%2f/gi, '/')
    .replace(/%5c/gi, '\\')
    .replace(/%2e/gi, '.')
    .replace(/%00/gi, '\0');
}

/** True when `kid` reads as traversal either as written or once decoded. */
function looksLikeTraversal(kid: string): boolean {
  return TRAVERSAL.test(kid) || TRAVERSAL.test(decodePathEscapes(kid));
}

/** True when `kid` reads as a filesystem path either as written or once decoded. */
function looksLikePath(kid: string): boolean {
  return PATH_SHAPED.test(kid) || PATH_SHAPED.test(decodePathEscapes(kid));
}
const SQL_META = /['"`;]|--|\/\*|\bunion\b|\|\||\bselect\b/i;

/** RFC 7797 is the only extension header in common use, so it is the only one treated as known. */
const KNOWN_CRIT_EXTENSIONS: readonly string[] = ['b64'];

export const RULES: readonly Rule[] = [
  {
    id: 'JWT-ALG-NONE',
    name: 'unsecured token (alg: none)',
    apply: (context) => {
      if (context.algorithm.family !== 'none' || isNoneVariant(context.algorithm)) return null;
      return {
        id: 'JWT-ALG-NONE',
        name: 'unsecured token (alg: none)',
        severity: 'critical',
        confirmed: false,
        rationale:
          'The token declares `alg: none`, the RFC 7515 unsecured JWS. Its integrity rests entirely on the verifier refusing to honour the header. A verifier that selects its algorithm from the token, rather than from its own configuration, will treat this as a valid signature-free assertion and every claim in it becomes attacker-controlled.',
        evidence: {
          alg: context.algorithm.declared,
          signatureBytes: context.token.signature.length,
          signatureSegmentEmpty: context.token.segments.signature.length === 0,
        },
      };
    },
  },
  {
    id: 'JWT-ALG-NONE-VARIANT',
    name: 'alg is a case variant of none',
    apply: (context) => {
      if (!isNoneVariant(context.algorithm)) return null;
      return {
        id: 'JWT-ALG-NONE-VARIANT',
        name: 'alg is a case variant of none',
        severity: 'high',
        confirmed: false,
        rationale:
          'The `alg` value differs from `none` only by case. Libraries that blocklisted the literal string `none` but compare case-insensitively elsewhere — or that upper-case the header before dispatch — have historically accepted exactly this. The presence of a case variant rather than the canonical spelling is a strong hint that the token was crafted against such a check.',
        evidence: { alg: context.algorithm.declared, canonicalSpelling: 'none' },
      };
    },
  },
  {
    id: 'JWT-SIG-EMPTY',
    name: 'empty signature on a signed algorithm',
    apply: (context) => {
      if (context.algorithm.family === 'none') return null;
      if (context.token.signature.length > 0) return null;
      return {
        id: 'JWT-SIG-EMPTY',
        name: 'empty signature on a signed algorithm',
        severity: 'high',
        confirmed: false,
        rationale:
          'The token names a signing algorithm but carries no signature bytes. Several verifiers short-circuit on an empty signature — returning early, or comparing an empty candidate against an empty supplied value — and so report success without performing any cryptography.',
        evidence: {
          alg: context.algorithm.declared,
          segmentCount: context.token.segmentCount,
        },
      };
    },
  },
  {
    id: 'JWT-ALG-UNKNOWN',
    name: 'algorithm name is not a registered one',
    apply: (context) => {
      const { algorithm } = context;
      if (algorithm.registered) return null;
      // A case variant of `none` has its own, more specific rule.
      if (algorithm.family === 'none') return null;
      return {
        id: 'JWT-ALG-UNKNOWN',
        name: 'algorithm name is not a registered one',
        severity: 'medium',
        confirmed: false,
        rationale:
          'The `alg` value is not an exact match for any registered JWS algorithm. How a verifier reacts is the interesting part: raising an error is correct, while falling through to a default, skipping verification, dispatching on a prefix match, or normalising the case before dispatch are all exploitable. A value that differs from a real algorithm only by case points at the last of those.',
        evidence: {
          alg: algorithm.declared,
          caseVariantOf: algorithm.caseVariantOf,
          inferredFamily: algorithm.family,
        },
      };
    },
  },
  {
    id: 'JWT-ALG-MISMATCH',
    name: 'header algorithm differs from the expected algorithm',
    apply: (context) => {
      if (context.expectAlg === null) return null;
      if (context.algorithm.declared === context.expectAlg) return null;
      return {
        id: 'JWT-ALG-MISMATCH',
        name: 'header algorithm differs from the expected algorithm',
        severity: 'high',
        confirmed: false,
        rationale:
          'You declared that this issuer signs with one algorithm and the token declares another. If the verifier reached its decision by reading the header rather than by pinning the algorithm it will accept, then the choice of algorithm — and therefore the choice of key material — belongs to whoever sent the token.',
        evidence: {
          declared: context.algorithm.declared,
          expected: context.expectAlg,
          declaredFamily: context.algorithm.family,
          expectedFamily: describeAlgorithm(context.expectAlg).family,
        },
      };
    },
  },
  {
    id: 'JWT-ALG-CONFUSION-HS',
    name: 'asymmetric public key used as an HMAC secret',
    apply: (context) => {
      const hit = context.evidence.confusion;
      if (hit === null) return null;
      return {
        id: 'JWT-ALG-CONFUSION-HS',
        name: 'asymmetric public key used as an HMAC secret',
        severity: 'critical',
        confirmed: true,
        rationale:
          'The signature on this token is a valid HMAC computed over the signing input with the supplied public key as the secret. This is algorithm confusion, and it is no longer a hypothesis: the MAC was recomputed locally and matched. Whatever produced or accepted this token selected its verification function from the `alg` header while holding a single key, so a public value became a signing key.',
        evidence: {
          keySource: hit.keySource,
          matchedRepresentation: hit.representation.label,
          representationDescription: hit.representation.description,
          hmacAlgorithm: context.algorithm.declared,
        },
      };
    },
  },
  {
    id: 'JWT-ALG-CONFUSION-CANDIDATE',
    name: 'algorithm confusion is testable against this issuer',
    apply: (context) => {
      const attempt = context.evidence.confusionCandidate;
      if (attempt === null) return null;
      return {
        id: 'JWT-ALG-CONFUSION-CANDIDATE',
        name: 'algorithm confusion is testable against this issuer',
        severity: 'info',
        confirmed: false,
        rationale:
          'The token is signed with an asymmetric algorithm and you have supplied the public key, which is the full set of prerequisites for an HS/RS confusion attempt. Nothing about the token says whether the verifier pins its algorithm; that can only be settled by presenting a candidate token. The attack matrix contains one per plausible byte representation of the key.',
        evidence: {
          keySource: attempt.keySource,
          declaredAlgorithm: context.algorithm.declared,
          representationsAvailable: attempt.representations,
        },
      };
    },
  },
  {
    id: 'JWT-WEAK-HMAC-SECRET',
    name: 'HMAC secret recovered from a list of common defaults',
    apply: (context) => {
      const hit = context.evidence.recoveredSecret;
      if (hit === null) return null;
      return {
        id: 'JWT-WEAK-HMAC-SECRET',
        name: 'HMAC secret recovered from a list of common defaults',
        severity: 'critical',
        confirmed: true,
        rationale:
          'The signing secret was recovered locally, so the signature on this token can be reproduced and any claim in it can be rewritten. An HMAC secret is a password with none of the protections passwords get: no rate limit, no lockout, and an offline oracle in every token the service hands out.',
        evidence: {
          secret: hit.secret === '' ? '(the empty string)' : hit.secret,
          origin: hit.origin,
          candidatesTried: context.secretListSize,
        },
      };
    },
  },
  {
    id: 'JWT-EMBEDDED-JWK',
    name: 'key supplied inside the token (jwk header)',
    apply: (context) => {
      const embedded = context.evidence.embeddedJwk;
      if (embedded === null) return null;
      return {
        id: 'JWT-EMBEDDED-JWK',
        name: 'key supplied inside the token (jwk header)',
        severity: 'critical',
        confirmed: false,
        rationale:
          'The header carries the public key the token wants to be verified against. A verifier that honours it is asking the token to vouch for itself, which is no check at all: the attacker generates a keypair, signs any claims they like, and attaches the public half. RFC 7515 permits the header; trusting it is the defect.',
        evidence: {
          keyType: embedded.keyType ?? '(unparseable)',
          usable: embedded.usable,
          parseError: embedded.error ?? null,
        },
      };
    },
  },
  {
    id: 'JWT-JWK-SELF-SIGNED',
    name: 'token verifies under its own embedded key',
    apply: (context) => {
      const embedded = context.evidence.embeddedJwk;
      if (embedded === null || !embedded.selfConsistent) return null;
      return {
        id: 'JWT-JWK-SELF-SIGNED',
        name: 'token verifies under its own embedded key',
        severity: 'critical',
        confirmed: true,
        rationale:
          'The signature verifies against the key in the token\'s own header. This was checked locally and holds. The token is internally consistent and entirely self-asserted, so a verifier that resolves keys from the `jwk` header will accept it, and would accept any other token built the same way.',
        evidence: {
          keyType: embedded.keyType ?? 'unknown',
          algorithm: context.algorithm.declared,
        },
      };
    },
  },
  {
    id: 'JWT-JKU-PRESENT',
    name: 'remote key set URL in the header (jku)',
    apply: (context) => {
      const jku = headerString(context, 'jku');
      if (jku === null) return null;
      return {
        id: 'JWT-JKU-PRESENT',
        name: 'remote key set URL in the header (jku)',
        severity: 'high',
        confirmed: false,
        rationale:
          'The header tells the verifier where to go and fetch the key set. That makes the verifier an HTTP client whose destination the attacker chooses — a server-side request forgery primitive in a code path that usually runs before authentication and often with generous egress — and, if the fetched key is then trusted, a complete signature bypass. jwt-confusion reports this URL and never requests it.',
        evidence: {
          jku,
          host: hostOf(jku),
          fetchedByThisTool: false,
        },
      };
    },
  },
  {
    id: 'JWT-X5U-PRESENT',
    name: 'remote certificate URL in the header (x5u)',
    apply: (context) => {
      const x5u = headerString(context, 'x5u');
      if (x5u === null) return null;
      return {
        id: 'JWT-X5U-PRESENT',
        name: 'remote certificate URL in the header (x5u)',
        severity: 'high',
        confirmed: false,
        rationale:
          'As with `jku`, the token nominates a URL the verifier will fetch, here an X.509 certificate chain. The same two consequences follow: an outbound request to an attacker-chosen host, and trust placed in material served by that host. jwt-confusion reports this URL and never requests it.',
        evidence: {
          x5u,
          host: hostOf(x5u),
          fetchedByThisTool: false,
        },
      };
    },
  },
  {
    id: 'JWT-KID-TRAVERSAL',
    name: 'path traversal in kid',
    apply: (context) => {
      const kid = headerString(context, 'kid');
      if (kid === null || !looksLikeTraversal(kid)) return null;
      return {
        id: 'JWT-KID-TRAVERSAL',
        name: 'path traversal in kid',
        severity: 'high',
        confirmed: false,
        rationale:
          'The key identifier contains path traversal. Where `kid` is used to build a filename, the attacker chooses which file becomes the verification key. The useful target is not a key at all: a file whose contents are empty or predictable lets the attacker compute the HMAC themselves, which is why `/dev/null` appears in the attack matrix.',
        evidence: { kid },
      };
    },
  },
  {
    id: 'JWT-KID-PATH',
    name: 'kid looks like a filesystem path',
    apply: (context) => {
      const kid = headerString(context, 'kid');
      if (kid === null) return null;
      if (looksLikeTraversal(kid) || URL_SHAPED.test(kid)) return null;
      if (!looksLikePath(kid)) return null;
      return {
        id: 'JWT-KID-PATH',
        name: 'kid looks like a filesystem path',
        severity: 'medium',
        confirmed: false,
        rationale:
          'The key identifier is path-shaped, which suggests the verifier resolves it against a directory on disk rather than looking it up in a fixed table. No traversal is present in this token, but the lookup it implies is the one worth probing.',
        evidence: { kid },
      };
    },
  },
  {
    id: 'JWT-KID-URL',
    name: 'kid is a URL',
    apply: (context) => {
      const kid = headerString(context, 'kid');
      if (kid === null || !URL_SHAPED.test(kid)) return null;
      return {
        id: 'JWT-KID-URL',
        name: 'kid is a URL',
        severity: 'high',
        confirmed: false,
        rationale:
          'A `kid` holding a URL implies the verifier dereferences it, which gives the same SSRF-and-then-trust shape as `jku` without even the pretence of a documented key-set format. jwt-confusion reports this URL and never requests it.',
        evidence: { kid, host: hostOf(kid), fetchedByThisTool: false },
      };
    },
  },
  {
    id: 'JWT-KID-SQLMETA',
    name: 'SQL metacharacters in kid',
    apply: (context) => {
      const kid = headerString(context, 'kid');
      if (kid === null || !SQL_META.test(kid)) return null;
      return {
        id: 'JWT-KID-SQLMETA',
        name: 'SQL metacharacters in kid',
        severity: 'high',
        confirmed: false,
        rationale:
          'The key identifier contains SQL metacharacters. Where keys live in a table and `kid` is interpolated into the lookup, the injection does more than read data: a `UNION SELECT` of a literal makes the attacker the author of the verification key, so the token can be signed with a value they already know.',
        evidence: { kid },
      };
    },
  },
  {
    id: 'JWT-SIG-LENGTH',
    name: 'signature length does not match the declared algorithm',
    apply: (context) => {
      const { algorithm, token } = context;
      const actual = token.signature.length;
      if (actual === 0) return null; // JWT-SIG-EMPTY covers this.

      if (algorithm.signatureBytes !== null && algorithm.family !== 'none') {
        if (actual === algorithm.signatureBytes) return null;
        return {
          id: 'JWT-SIG-LENGTH',
          name: 'signature length does not match the declared algorithm',
          severity: 'high',
          confirmed: false,
          rationale:
            'The signature is not the length this algorithm produces. A truncated signature is the interesting case: a verifier that compares only as many bytes as it was given reduces the work of forging one from infeasible to trivial, and a few libraries have shipped exactly that comparison.',
          evidence: {
            alg: algorithm.declared,
            expectedBytes: algorithm.signatureBytes,
            actualBytes: actual,
            truncated: actual < algorithm.signatureBytes,
          },
        };
      }

      if (algorithm.family === 'rsa' || algorithm.family === 'rsa-pss') {
        if (RSA_SIGNATURE_LENGTHS.includes(actual)) return null;
        return {
          id: 'JWT-SIG-LENGTH',
          name: 'signature length does not match the declared algorithm',
          severity: 'high',
          confirmed: false,
          rationale:
            'An RSA signature is exactly as long as the modulus, so its length must be one of the common key sizes. This one is not, which means either the signature has been altered or the key is an unusual size. The token alone cannot distinguish the two; supply the public key and the analyser will say which.',
          evidence: {
            alg: algorithm.declared,
            actualBytes: actual,
            plausibleLengths: RSA_SIGNATURE_LENGTHS.map(String),
          },
        };
      }

      if (algorithm.family === 'none') {
        return {
          id: 'JWT-SIG-LENGTH',
          name: 'signature length does not match the declared algorithm',
          severity: 'high',
          confirmed: false,
          rationale:
            'The token declares an unsecured JWS but still carries signature bytes. This is the shape produced by stripping an algorithm from a signed token while leaving the signature in place, and a verifier that checks only for the presence of a signature segment will be satisfied by it.',
          evidence: { alg: algorithm.declared, expectedBytes: 0, actualBytes: actual },
        };
      }

      return null;
    },
  },
  {
    id: 'JWT-RSA-SMALL-KEY',
    name: 'RSA signature implies a small modulus',
    apply: (context) => {
      const { algorithm, token, evidence } = context;
      if (algorithm.family !== 'rsa' && algorithm.family !== 'rsa-pss') return null;
      const bits = evidence.rsaKeyBits ?? token.signature.length * 8;
      if (bits > 1024) return null;
      if (token.signature.length === 0) return null;
      return {
        id: 'JWT-RSA-SMALL-KEY',
        name: 'RSA signature implies a small modulus',
        severity: 'medium',
        confirmed: evidence.rsaKeyBits !== null,
        rationale:
          'The key is at most 1024 bits. RFC 7518 §3.3 requires a minimum of 2048 for RS256 and above, and 1024-bit RSA has been outside the recommended range for general use since 2010. This is a key-management finding rather than a forgeable one.',
        evidence: {
          bits,
          source: evidence.rsaKeyBits !== null ? 'the supplied public key' : 'inferred from signature length',
        },
      };
    },
  },
  {
    id: 'JWT-ECDSA-ZERO-SIG',
    name: 'ECDSA signature with zero r and s',
    apply: (context) => {
      if (!context.evidence.ecdsaZeroSignature) return null;
      return {
        id: 'JWT-ECDSA-ZERO-SIG',
        name: 'ECDSA signature with zero r and s',
        severity: 'critical',
        confirmed: true,
        rationale:
          'Both halves of the ECDSA signature are zero. The verification equation accepts this for any message unless the implementation explicitly rejects r = 0 or s = 0, which is the defect behind CVE-2022-21449 in the JDK\'s own ECDSA provider (Java 15 to 18). A verifier built on an affected runtime accepts this token without holding any key material at all.',
        evidence: {
          alg: context.algorithm.declared,
          signatureBytes: context.token.signature.length,
          affectedRuntimes: 'Java 15-18 (CVE-2022-21449); unaffected elsewhere',
        },
      };
    },
  },
  {
    id: 'JWT-B64-NONCANONICAL',
    name: 'non-canonical base64url encoding',
    apply: (context) => {
      const issues = context.token.encodingIssues;
      if (issues.length === 0) return null;
      return {
        id: 'JWT-B64-NONCANONICAL',
        name: 'non-canonical base64url encoding',
        severity: 'medium',
        confirmed: false,
        rationale:
          'At least one segment is not canonical base64url. Only a lenient decoder accepts this, and a lenient decoder means two encodings of the same bytes both reach the application. Where one component checks claims and another re-decodes the token, they can be made to disagree — and because the signature covers the segment bytes rather than the decoded JSON, the attacker may be able to change what the second component sees without touching the signature.',
        evidence: {
          affectedSegments: Array.from(new Set(issues.map((issue) => issue.segment))),
          issues: issues.map((issue) => `${issue.segment}: ${issue.issue}`),
        },
      };
    },
  },
  {
    id: 'JWT-CRIT-UNKNOWN',
    name: 'crit header names extensions outside the known set',
    apply: (context) => {
      const crit = context.token.header['crit'];
      if (crit === undefined) return null;

      if (!Array.isArray(crit) || crit.length === 0 || crit.some((entry) => typeof entry !== 'string')) {
        return {
          id: 'JWT-CRIT-UNKNOWN',
          name: 'crit header names extensions outside the known set',
          severity: 'medium',
          confirmed: false,
          rationale:
            'RFC 7515 §4.1.11 requires `crit` to be a non-empty array of strings. This one is not, and a verifier is obliged to reject the token. One that does not is not validating the header it is about to act on.',
          evidence: { crit: JSON.stringify(crit), malformed: true },
        };
      }

      const names = crit as string[];
      const unknown = names.filter((name) => !KNOWN_CRIT_EXTENSIONS.includes(name));
      const absent = names.filter((name) => !Object.prototype.hasOwnProperty.call(context.token.header, name));
      if (unknown.length === 0 && absent.length === 0) return null;

      return {
        id: 'JWT-CRIT-UNKNOWN',
        name: 'crit header names extensions outside the known set',
        severity: 'medium',
        confirmed: false,
        rationale:
          'The `crit` header marks extensions the verifier must understand or else reject the token. Entries that are unrecognised, or that name a header parameter which is not present, mean the verifier is being asked to honour something undefined. Correct behaviour is rejection; a verifier that instead ignores `crit` has silently discarded a processing instruction the signature covers.',
        evidence: {
          crit: names,
          unrecognised: unknown,
          namedButAbsentFromHeader: absent,
        },
      };
    },
  },
  {
    id: 'JWT-NO-EXP',
    name: 'no expiry claim',
    apply: (context) => {
      if (context.token.payload === null) return null;
      if (claimNumber(context, 'exp') !== null) return null;
      return {
        id: 'JWT-NO-EXP',
        name: 'no expiry claim',
        severity: 'high',
        confirmed: false,
        rationale:
          'The token carries no `exp`. Unless the verifier requires one, this token is valid until the signing key is rotated, which in practice means indefinitely. Any copy that leaks — from a log, a proxy cache, a browser history, a support ticket — remains a working credential.',
        evidence: { claimsPresent: Object.keys(context.token.payload) },
      };
    },
  },
  {
    id: 'JWT-LONG-EXP',
    name: 'excessive token lifetime',
    apply: (context) => {
      const exp = claimNumber(context, 'exp');
      if (exp === null) return null;
      const iat = claimNumber(context, 'iat');
      const nowSeconds = Math.floor(context.now.getTime() / 1000);
      const start = iat ?? nowSeconds;
      const lifetime = exp - start;
      if (lifetime <= context.maxLifetimeSeconds) return null;
      return {
        id: 'JWT-LONG-EXP',
        name: 'excessive token lifetime',
        severity: 'medium',
        confirmed: false,
        rationale:
          'The validity window is longer than the configured threshold. A long-lived bearer token behaves like a password that cannot be changed: revocation needs either a key rotation that invalidates every other token, or the denylist the stateless design was adopted to avoid.',
        evidence: {
          lifetimeSeconds: lifetime,
          lifetimeDays: Number((lifetime / 86400).toFixed(2)),
          thresholdDays: Number((context.maxLifetimeSeconds / 86400).toFixed(2)),
          measuredFrom: iat === null ? 'the current time (no iat claim)' : 'the iat claim',
        },
      };
    },
  },
  {
    id: 'JWT-EXPIRED',
    name: 'token is already expired',
    apply: (context) => {
      const exp = claimNumber(context, 'exp');
      if (exp === null) return null;
      const nowSeconds = Math.floor(context.now.getTime() / 1000);
      if (exp > nowSeconds) return null;
      return {
        id: 'JWT-EXPIRED',
        name: 'token is already expired',
        severity: 'info',
        confirmed: false,
        rationale:
          'The token is past its expiry against the clock used for this analysis. That is noted here because it changes how the rest of the output should be read: if the target still accepts this token, expiry is not being enforced, and that is a finding in its own right which no amount of offline analysis can establish.',
        evidence: {
          exp,
          expAt: new Date(exp * 1000).toISOString(),
          expiredBySeconds: nowSeconds - exp,
          comparedAgainst: context.now.toISOString(),
        },
      };
    },
  },
  {
    id: 'JWT-NO-AUD',
    name: 'no audience claim',
    apply: (context) => {
      if (context.token.payload === null) return null;
      if (context.token.payload['aud'] !== undefined) return null;
      return {
        id: 'JWT-NO-AUD',
        name: 'no audience claim',
        severity: 'medium',
        confirmed: false,
        rationale:
          'Without `aud`, nothing in the token says which service it was minted for. Every service that trusts this issuer will accept it, so a token issued for a low-value API is replayable against a high-value one. This is the claim that makes a token confused-deputy-resistant, and it is the one most often left out.',
        evidence: { claimsPresent: Object.keys(context.token.payload) },
      };
    },
  },
  {
    id: 'JWT-NO-ISS',
    name: 'no issuer claim',
    apply: (context) => {
      if (context.token.payload === null) return null;
      if (context.token.payload['iss'] !== undefined) return null;
      return {
        id: 'JWT-NO-ISS',
        name: 'no issuer claim',
        severity: 'low',
        confirmed: false,
        rationale:
          'Without `iss`, a verifier that trusts more than one issuer cannot tell them apart, and key selection has to fall back on something less trustworthy — usually `kid`, which the attacker also controls.',
        evidence: { claimsPresent: Object.keys(context.token.payload) },
      };
    },
  },
];

export const RULE_IDS: readonly string[] = RULES.map((rule) => rule.id);

export function runRules(context: RuleContext): Finding[] {
  const findings: Finding[] = [];
  for (const rule of RULES) {
    const result = rule.apply(context);
    if (result === null) continue;
    if (Array.isArray(result)) findings.push(...result);
    else findings.push(result);
  }
  return findings;
}
