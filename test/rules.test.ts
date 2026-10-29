import assert from 'node:assert/strict';
import { test } from 'node:test';

import { analyseToken } from '../src/analyse.js';
import { describeAlgorithm } from '../src/algorithms.js';
import { encodeBase64url, encodeJsonBase64url } from '../src/base64url.js';
import { hmac, loadKeysFromText, publicKeyToJwk, signAsymmetric } from '../src/crypto.js';
import { RULE_IDS } from '../src/rules.js';
import type { Finding } from '../src/types.js';

import { deterministicEd25519, ecPair, makeToken, rsaPair, spkiPem, wellFormedClaims } from './keys.js';

const NOW = new Date(1760000000 * 1000);

function ids(findings: readonly Finding[]): string[] {
  return findings.map((finding) => finding.id);
}

function finding(findings: readonly Finding[], id: string): Finding {
  const match = findings.find((entry) => entry.id === id);
  assert.ok(match !== undefined, `expected finding ${id}, got ${ids(findings).join(', ') || 'none'}`);
  return match;
}

function hs256(header: Record<string, unknown>, payload: Record<string, unknown>, secret: string): string {
  const headerSegment = encodeJsonBase64url(header);
  const payloadSegment = encodeJsonBase64url(payload);
  const mac = hmac(describeAlgorithm('HS256'), Buffer.from(secret, 'utf8'), `${headerSegment}.${payloadSegment}`);
  return `${headerSegment}.${payloadSegment}.${encodeBase64url(mac)}`;
}

test('rule ids are unique', () => {
  assert.equal(new Set(RULE_IDS).size, RULE_IDS.length);
  assert.ok(RULE_IDS.length >= 20);
});

test('a well-formed token raises no claim-hygiene findings', () => {
  const token = hs256({ alg: 'HS256', typ: 'JWT', kid: 'signing-2026-01' }, wellFormedClaims(), 'an-unguessable-value-9f2a');
  const { findings } = analyseToken(token, { now: NOW, includeAttacks: false });
  for (const id of ['JWT-NO-EXP', 'JWT-NO-AUD', 'JWT-NO-ISS', 'JWT-EXPIRED', 'JWT-LONG-EXP']) {
    assert.ok(!ids(findings).includes(id), `${id} should not fire: ${ids(findings).join(', ')}`);
  }
  for (const id of ['JWT-KID-TRAVERSAL', 'JWT-KID-PATH', 'JWT-KID-URL', 'JWT-KID-SQLMETA']) {
    assert.ok(!ids(findings).includes(id), `${id} should not fire for a plain kid`);
  }
  assert.ok(!ids(findings).includes('JWT-WEAK-HMAC-SECRET'));
  assert.ok(!ids(findings).includes('JWT-B64-NONCANONICAL'));
});

test('JWT-ALG-NONE fires for the canonical spelling only', () => {
  const unsecured = analyseToken(makeToken({ alg: 'none', typ: 'JWT' }, wellFormedClaims()), {
    now: NOW,
    includeAttacks: false,
  });
  const none = finding(unsecured.findings, 'JWT-ALG-NONE');
  assert.equal(none.severity, 'critical');
  assert.equal(none.confirmed, false);
  assert.equal(none.evidence['signatureSegmentEmpty'], true);
  assert.ok(!ids(unsecured.findings).includes('JWT-ALG-NONE-VARIANT'));
});

test('JWT-ALG-NONE-VARIANT fires for a case variant instead', () => {
  const analysis = analyseToken(makeToken({ alg: 'None' }, wellFormedClaims()), {
    now: NOW,
    includeAttacks: false,
  });
  const variant = finding(analysis.findings, 'JWT-ALG-NONE-VARIANT');
  assert.equal(variant.severity, 'high');
  assert.equal(variant.evidence['canonicalSpelling'], 'none');
  assert.ok(!ids(analysis.findings).includes('JWT-ALG-NONE'));
  assert.equal(analysis.structure.algorithm.caseVariantOf, 'none');
  assert.equal(analysis.structure.algorithm.registered, false);
});

test('JWT-SIG-EMPTY fires when a signed algorithm carries no signature', () => {
  const analysis = analyseToken(makeToken({ alg: 'HS256' }, wellFormedClaims()), {
    now: NOW,
    includeAttacks: false,
  });
  assert.equal(finding(analysis.findings, 'JWT-SIG-EMPTY').severity, 'high');
  assert.ok(!ids(analysis.findings).includes('JWT-SIG-LENGTH'));
});

test('JWT-ALG-UNKNOWN fires for an unrecognised algorithm name', () => {
  const analysis = analyseToken(makeToken({ alg: 'HS257' }, wellFormedClaims(), Buffer.alloc(32)), {
    now: NOW,
    includeAttacks: false,
  });
  assert.equal(finding(analysis.findings, 'JWT-ALG-UNKNOWN').evidence['alg'], 'HS257');
  assert.equal(analysis.structure.algorithm.family, 'unknown');
});

test('JWT-ALG-MISMATCH fires only when the header disagrees with --expect-alg', () => {
  const token = hs256({ alg: 'HS256' }, wellFormedClaims(), 'an-unguessable-value-9f2a');
  const mismatch = analyseToken(token, { now: NOW, includeAttacks: false, expectAlg: 'RS256' });
  const hit = finding(mismatch.findings, 'JWT-ALG-MISMATCH');
  assert.equal(hit.evidence['declaredFamily'], 'hmac');
  assert.equal(hit.evidence['expectedFamily'], 'rsa');

  const agreed = analyseToken(token, { now: NOW, includeAttacks: false, expectAlg: 'HS256' });
  assert.ok(!ids(agreed.findings).includes('JWT-ALG-MISMATCH'));
});

test('JWT-ALG-CONFUSION-HS is confirmed by recomputing the MAC with the key file bytes', () => {
  const { publicKey } = rsaPair();
  const pem = spkiPem(publicKey);
  const keys = loadKeysFromText(pem, 'issuer-public.pem', Buffer.from(pem, 'utf8'));

  const headerSegment = encodeJsonBase64url({ alg: 'HS256', typ: 'JWT' });
  const payloadSegment = encodeJsonBase64url(wellFormedClaims());
  const mac = hmac(describeAlgorithm('HS256'), Buffer.from(pem, 'utf8'), `${headerSegment}.${payloadSegment}`);
  const forged = `${headerSegment}.${payloadSegment}.${encodeBase64url(mac)}`;

  const analysis = analyseToken(forged, { now: NOW, includeAttacks: false, keys });
  const hit = finding(analysis.findings, 'JWT-ALG-CONFUSION-HS');
  assert.equal(hit.severity, 'critical');
  assert.equal(hit.confirmed, true);
  assert.equal(hit.evidence['matchedRepresentation'], 'file-bytes');
  assert.equal(hit.evidence['keySource'], 'issuer-public.pem');
  assert.ok(analysis.structure.signatureVerification.some((result) => result.valid));
});

test('a genuine RS256 token with the same key raises no confirmed confusion finding', () => {
  const { publicKey, privateKey } = rsaPair();
  const pem = spkiPem(publicKey);
  const keys = loadKeysFromText(pem, 'issuer-public.pem', Buffer.from(pem, 'utf8'));

  const headerSegment = encodeJsonBase64url({ alg: 'RS256', typ: 'JWT' });
  const payloadSegment = encodeJsonBase64url(wellFormedClaims());
  const signature = signAsymmetric(describeAlgorithm('RS256'), privateKey, `${headerSegment}.${payloadSegment}`);
  const token = `${headerSegment}.${payloadSegment}.${encodeBase64url(signature)}`;

  const analysis = analyseToken(token, { now: NOW, includeAttacks: false, keys });
  assert.ok(!ids(analysis.findings).includes('JWT-ALG-CONFUSION-HS'));
  const candidate = finding(analysis.findings, 'JWT-ALG-CONFUSION-CANDIDATE');
  assert.equal(candidate.severity, 'info');
  assert.equal(candidate.confirmed, false);
  assert.ok(Number(candidate.evidence['representationsAvailable']) >= 4);
  assert.deepEqual(
    analysis.structure.signatureVerification.map((result) => result.valid),
    [true],
  );
});

test('an HMAC token analysed with an unrelated public key reports no confusion and says why', () => {
  const { publicKey } = rsaPair();
  const pem = spkiPem(publicKey);
  const keys = loadKeysFromText(pem, 'issuer-public.pem', Buffer.from(pem, 'utf8'));
  const token = hs256({ alg: 'HS256' }, wellFormedClaims(), 'an-unguessable-value-9f2a');
  const analysis = analyseToken(token, { now: NOW, includeAttacks: false, keys });
  assert.ok(!ids(analysis.findings).includes('JWT-ALG-CONFUSION-HS'));
  assert.ok(analysis.notes.some((note) => note.includes('no byte representation')));
});

test('JWT-WEAK-HMAC-SECRET recovers a list secret and an empty secret', () => {
  const listed = analyseToken(hs256({ alg: 'HS256' }, wellFormedClaims(), 'changeme'), {
    now: NOW,
    includeAttacks: false,
  });
  const hit = finding(listed.findings, 'JWT-WEAK-HMAC-SECRET');
  assert.equal(hit.confirmed, true);
  assert.equal(hit.evidence['secret'], 'changeme');
  assert.equal(hit.evidence['origin'], 'built-in list of common defaults');

  const empty = analyseToken(hs256({ alg: 'HS256' }, wellFormedClaims(), ''), {
    now: NOW,
    includeAttacks: false,
  });
  assert.equal(finding(empty.findings, 'JWT-WEAK-HMAC-SECRET').evidence['secret'], '(the empty string)');
});

test('a secret supplied by the caller is tried before the built-in list', () => {
  const token = hs256({ alg: 'HS256' }, wellFormedClaims(), 'correct-horse-battery-staple');
  const withSecret = analyseToken(token, {
    now: NOW,
    includeAttacks: false,
    hmacSecret: 'correct-horse-battery-staple',
  });
  assert.equal(
    finding(withSecret.findings, 'JWT-WEAK-HMAC-SECRET').evidence['origin'],
    'supplied with --hmac-secret',
  );

  const extraList = analyseToken(token, {
    now: NOW,
    includeAttacks: false,
    extraSecrets: ['nope', 'correct-horse-battery-staple'],
  });
  assert.equal(
    finding(extraList.findings, 'JWT-WEAK-HMAC-SECRET').evidence['origin'],
    'supplied with --secret-list',
  );

  const wrongSecret = analyseToken(token, { now: NOW, includeAttacks: false, hmacSecret: 'wrong' });
  assert.ok(!ids(wrongSecret.findings).includes('JWT-WEAK-HMAC-SECRET'));
  assert.deepEqual(
    wrongSecret.structure.signatureVerification.map((result) => result.valid),
    [false],
  );
});

test('JWT-EMBEDDED-JWK and JWT-JWK-SELF-SIGNED both fire for a self-signed token', () => {
  const { publicKey, privateKey } = rsaPair();
  const header = { alg: 'RS256', typ: 'JWT', jwk: publicKeyToJwk(publicKey) };
  const headerSegment = encodeJsonBase64url(header);
  const payloadSegment = encodeJsonBase64url(wellFormedClaims());
  const signature = signAsymmetric(describeAlgorithm('RS256'), privateKey, `${headerSegment}.${payloadSegment}`);
  const token = `${headerSegment}.${payloadSegment}.${encodeBase64url(signature)}`;

  const analysis = analyseToken(token, { now: NOW, includeAttacks: false });
  assert.equal(finding(analysis.findings, 'JWT-EMBEDDED-JWK').severity, 'critical');
  assert.equal(finding(analysis.findings, 'JWT-EMBEDDED-JWK').confirmed, false);
  const selfSigned = finding(analysis.findings, 'JWT-JWK-SELF-SIGNED');
  assert.equal(selfSigned.confirmed, true);
  assert.equal(selfSigned.evidence['keyType'], 'rsa');
  assert.ok(analysis.structure.keyLocatorHeaders.includes('jwk'));
});

test('an embedded jwk that does not match the signature reports only the header finding', () => {
  const { publicKey } = rsaPair();
  const header = { alg: 'RS256', typ: 'JWT', jwk: publicKeyToJwk(publicKey) };
  const token = makeToken(header, wellFormedClaims(), Buffer.alloc(256, 9));
  const analysis = analyseToken(token, { now: NOW, includeAttacks: false });
  assert.equal(finding(analysis.findings, 'JWT-EMBEDDED-JWK').evidence['usable'], true);
  assert.ok(!ids(analysis.findings).includes('JWT-JWK-SELF-SIGNED'));
});

test('an unparseable embedded jwk is reported rather than crashing', () => {
  const token = makeToken({ alg: 'RS256', jwk: { kty: 'nonsense' } }, wellFormedClaims(), Buffer.alloc(256));
  const analysis = analyseToken(token, { now: NOW, includeAttacks: false });
  const hit = finding(analysis.findings, 'JWT-EMBEDDED-JWK');
  assert.equal(hit.evidence['usable'], false);
  assert.ok(String(hit.evidence['parseError']).length > 0);
});

test('JWT-JKU-PRESENT and JWT-X5U-PRESENT report the host and record that nothing was fetched', () => {
  const token = makeToken(
    { alg: 'RS256', jku: 'https://keys.internal.example/jwks.json', x5u: 'http://169.254.169.254/latest/meta-data/' },
    wellFormedClaims(),
    Buffer.alloc(256),
  );
  const analysis = analyseToken(token, { now: NOW, includeAttacks: false });
  const jku = finding(analysis.findings, 'JWT-JKU-PRESENT');
  assert.equal(jku.severity, 'high');
  assert.equal(jku.evidence['host'], 'keys.internal.example');
  assert.equal(jku.evidence['fetchedByThisTool'], false);
  const x5u = finding(analysis.findings, 'JWT-X5U-PRESENT');
  assert.equal(x5u.evidence['host'], '169.254.169.254');
  assert.equal(x5u.evidence['fetchedByThisTool'], false);
});

test('kid rules classify traversal, paths, URLs and SQL metacharacters separately', () => {
  const traversal = analyseToken(
    makeToken({ alg: 'HS256', kid: '../../../../dev/null' }, wellFormedClaims(), Buffer.alloc(32)),
    { now: NOW, includeAttacks: false },
  );
  assert.equal(finding(traversal.findings, 'JWT-KID-TRAVERSAL').severity, 'high');
  assert.ok(!ids(traversal.findings).includes('JWT-KID-PATH'));

  const path = analyseToken(
    makeToken({ alg: 'HS256', kid: '/etc/app/keys/signing.pem' }, wellFormedClaims(), Buffer.alloc(32)),
    { now: NOW, includeAttacks: false },
  );
  assert.equal(finding(path.findings, 'JWT-KID-PATH').severity, 'medium');
  assert.ok(!ids(path.findings).includes('JWT-KID-TRAVERSAL'));

  const url = analyseToken(
    makeToken({ alg: 'HS256', kid: 'https://keys.example/signing' }, wellFormedClaims(), Buffer.alloc(32)),
    { now: NOW, includeAttacks: false },
  );
  assert.equal(finding(url.findings, 'JWT-KID-URL').evidence['host'], 'keys.example');
  assert.ok(!ids(url.findings).includes('JWT-KID-PATH'));

  const sql = analyseToken(
    makeToken({ alg: 'HS256', kid: "nonexistent' UNION SELECT 'k" }, wellFormedClaims(), Buffer.alloc(32)),
    { now: NOW, includeAttacks: false },
  );
  assert.equal(finding(sql.findings, 'JWT-KID-SQLMETA').severity, 'high');

  const urlEncoded = analyseToken(
    makeToken({ alg: 'HS256', kid: 'keys%2e%2e%2fsigning' }, wellFormedClaims(), Buffer.alloc(32)),
    { now: NOW, includeAttacks: false },
  );
  assert.ok(ids(urlEncoded.findings).includes('JWT-KID-TRAVERSAL'));
});

test('JWT-SIG-LENGTH catches a truncated fixed-length signature', () => {
  const analysis = analyseToken(makeToken({ alg: 'HS256' }, wellFormedClaims(), Buffer.alloc(16)), {
    now: NOW,
    includeAttacks: false,
  });
  const hit = finding(analysis.findings, 'JWT-SIG-LENGTH');
  assert.equal(hit.evidence['expectedBytes'], 32);
  assert.equal(hit.evidence['actualBytes'], 16);
  assert.equal(hit.evidence['truncated'], true);
});

test('JWT-SIG-LENGTH accepts every plausible RSA modulus size and rejects others', () => {
  for (const size of [256, 384, 512]) {
    const analysis = analyseToken(makeToken({ alg: 'RS256' }, wellFormedClaims(), Buffer.alloc(size)), {
      now: NOW,
      includeAttacks: false,
    });
    assert.ok(!ids(analysis.findings).includes('JWT-SIG-LENGTH'), `${size} bytes should be plausible`);
  }
  const odd = analyseToken(makeToken({ alg: 'RS256' }, wellFormedClaims(), Buffer.alloc(300)), {
    now: NOW,
    includeAttacks: false,
  });
  assert.equal(finding(odd.findings, 'JWT-SIG-LENGTH').evidence['actualBytes'], 300);
});

test('JWT-SIG-LENGTH fires when an unsecured token still carries signature bytes', () => {
  const analysis = analyseToken(makeToken({ alg: 'none' }, wellFormedClaims(), Buffer.alloc(32, 1)), {
    now: NOW,
    includeAttacks: false,
  });
  const hit = finding(analysis.findings, 'JWT-SIG-LENGTH');
  assert.equal(hit.evidence['expectedBytes'], 0);
  assert.equal(hit.evidence['actualBytes'], 32);
});

test('JWT-RSA-SMALL-KEY is inferred from the signature length and confirmed from a key', () => {
  const inferred = analyseToken(makeToken({ alg: 'RS256' }, wellFormedClaims(), Buffer.alloc(128)), {
    now: NOW,
    includeAttacks: false,
  });
  const hit = finding(inferred.findings, 'JWT-RSA-SMALL-KEY');
  assert.equal(hit.confirmed, false);
  assert.equal(hit.evidence['bits'], 1024);
  assert.match(String(hit.evidence['source']), /inferred/);

  const { publicKey } = rsaPair();
  const pem = spkiPem(publicKey);
  const keys = loadKeysFromText(pem, 'issuer-public.pem', Buffer.from(pem, 'utf8'));
  const withKey = analyseToken(makeToken({ alg: 'RS256' }, wellFormedClaims(), Buffer.alloc(256)), {
    now: NOW,
    includeAttacks: false,
    keys,
  });
  assert.ok(!ids(withKey.findings).includes('JWT-RSA-SMALL-KEY'));
});

test('JWT-ECDSA-ZERO-SIG fires for an all-zero ECDSA signature only', () => {
  const zeros = analyseToken(makeToken({ alg: 'ES256' }, wellFormedClaims(), Buffer.alloc(64)), {
    now: NOW,
    includeAttacks: false,
  });
  const hit = finding(zeros.findings, 'JWT-ECDSA-ZERO-SIG');
  assert.equal(hit.confirmed, true);
  assert.match(hit.rationale, /CVE-2022-21449/);

  const { publicKey, privateKey } = ecPair();
  const headerSegment = encodeJsonBase64url({ alg: 'ES256' });
  const payloadSegment = encodeJsonBase64url(wellFormedClaims());
  const signature = signAsymmetric(describeAlgorithm('ES256'), privateKey, `${headerSegment}.${payloadSegment}`);
  const real = `${headerSegment}.${payloadSegment}.${encodeBase64url(signature)}`;
  const pem = spkiPem(publicKey);
  const analysis = analyseToken(real, {
    now: NOW,
    includeAttacks: false,
    keys: loadKeysFromText(pem, 'ec-public.pem', Buffer.from(pem, 'utf8')),
  });
  assert.ok(!ids(analysis.findings).includes('JWT-ECDSA-ZERO-SIG'));
  assert.equal(signature.length, 64, 'ES256 signatures are raw r||s, not DER');
  assert.deepEqual(
    analysis.structure.signatureVerification.map((result) => result.valid),
    [true],
  );
});

test('an Ed25519 token verifies under a deterministically derived key', () => {
  const { publicKey, privateKey } = deterministicEd25519();
  const headerSegment = encodeJsonBase64url({ alg: 'EdDSA' });
  const payloadSegment = encodeJsonBase64url(wellFormedClaims());
  const signature = signAsymmetric(describeAlgorithm('EdDSA'), privateKey, `${headerSegment}.${payloadSegment}`);
  assert.equal(signature.length, 64);
  const token = `${headerSegment}.${payloadSegment}.${encodeBase64url(signature)}`;
  const pem = spkiPem(publicKey);
  const analysis = analyseToken(token, {
    now: NOW,
    includeAttacks: false,
    keys: loadKeysFromText(pem, 'ed25519-public.pem', Buffer.from(pem, 'utf8')),
  });
  assert.deepEqual(
    analysis.structure.signatureVerification.map((result) => result.valid),
    [true],
  );
  assert.ok(!ids(analysis.findings).includes('JWT-SIG-LENGTH'));
});

test('JWT-B64-NONCANONICAL reports the affected segment', () => {
  const headerSegment = encodeJsonBase64url({ alg: 'HS256' });
  const payloadSegment = `${encodeJsonBase64url(wellFormedClaims())}==`;
  const analysis = analyseToken(`${headerSegment}.${payloadSegment}.${encodeBase64url(Buffer.alloc(32))}`, {
    now: NOW,
    includeAttacks: false,
  });
  const hit = finding(analysis.findings, 'JWT-B64-NONCANONICAL');
  assert.equal(hit.severity, 'medium');
  assert.deepEqual(hit.evidence['affectedSegments'], ['payload']);
});

test('JWT-CRIT-UNKNOWN fires for unknown entries, absent entries and malformed values', () => {
  const unknown = analyseToken(
    makeToken({ alg: 'HS256', crit: ['vendor-ext'], 'vendor-ext': 1 }, wellFormedClaims(), Buffer.alloc(32)),
    { now: NOW, includeAttacks: false },
  );
  assert.deepEqual(finding(unknown.findings, 'JWT-CRIT-UNKNOWN').evidence['unrecognised'], ['vendor-ext']);

  const absent = analyseToken(
    makeToken({ alg: 'HS256', crit: ['b64'] }, wellFormedClaims(), Buffer.alloc(32)),
    { now: NOW, includeAttacks: false },
  );
  assert.deepEqual(finding(absent.findings, 'JWT-CRIT-UNKNOWN').evidence['namedButAbsentFromHeader'], ['b64']);

  const wellFormed = analyseToken(
    makeToken({ alg: 'HS256', crit: ['b64'], b64: false }, wellFormedClaims(), Buffer.alloc(32)),
    { now: NOW, includeAttacks: false },
  );
  assert.ok(!ids(wellFormed.findings).includes('JWT-CRIT-UNKNOWN'));

  const malformed = analyseToken(
    makeToken({ alg: 'HS256', crit: 'b64' }, wellFormedClaims(), Buffer.alloc(32)),
    { now: NOW, includeAttacks: false },
  );
  assert.equal(finding(malformed.findings, 'JWT-CRIT-UNKNOWN').evidence['malformed'], true);
});

test('claim-hygiene rules fire on the claims they name', () => {
  const bare = analyseToken(makeToken({ alg: 'HS256' }, { sub: 'a' }, Buffer.alloc(32)), {
    now: NOW,
    includeAttacks: false,
  });
  assert.equal(finding(bare.findings, 'JWT-NO-EXP').severity, 'high');
  assert.equal(finding(bare.findings, 'JWT-NO-AUD').severity, 'medium');
  assert.equal(finding(bare.findings, 'JWT-NO-ISS').severity, 'low');
  assert.equal(bare.structure.expired, null);
  assert.equal(bare.structure.lifetimeSeconds, null);
});

test('JWT-LONG-EXP measures from iat when present and from the clock otherwise', () => {
  const nowSeconds = 1760000000;
  const fromIat = analyseToken(
    makeToken({ alg: 'HS256' }, { iat: nowSeconds, exp: nowSeconds + 400 * 86400 }, Buffer.alloc(32)),
    { now: NOW, includeAttacks: false },
  );
  const hit = finding(fromIat.findings, 'JWT-LONG-EXP');
  assert.equal(hit.evidence['lifetimeDays'], 400);
  assert.match(String(hit.evidence['measuredFrom']), /iat/);
  assert.equal(fromIat.structure.lifetimeSeconds, 400 * 86400);

  const noIat = analyseToken(makeToken({ alg: 'HS256' }, { exp: nowSeconds + 400 * 86400 }, Buffer.alloc(32)), {
    now: NOW,
    includeAttacks: false,
  });
  assert.match(String(finding(noIat.findings, 'JWT-LONG-EXP').evidence['measuredFrom']), /current time/);

  const raisedThreshold = analyseToken(
    makeToken({ alg: 'HS256' }, { iat: nowSeconds, exp: nowSeconds + 400 * 86400 }, Buffer.alloc(32)),
    { now: NOW, includeAttacks: false, maxLifetimeDays: 500 },
  );
  assert.ok(!ids(raisedThreshold.findings).includes('JWT-LONG-EXP'));
});

test('JWT-EXPIRED is informational and reports how long ago it lapsed', () => {
  const nowSeconds = 1760000000;
  const analysis = analyseToken(
    makeToken({ alg: 'HS256' }, { iat: nowSeconds - 7200, exp: nowSeconds - 3600 }, Buffer.alloc(32)),
    { now: NOW, includeAttacks: false },
  );
  const hit = finding(analysis.findings, 'JWT-EXPIRED');
  assert.equal(hit.severity, 'info');
  assert.equal(hit.evidence['expiredBySeconds'], 3600);
  assert.equal(analysis.structure.expired, true);
});

test('findings are ordered by severity, with confirmed findings first within a severity', () => {
  const token = hs256({ alg: 'HS256', kid: '../../../../dev/null' }, { sub: 'a' }, 'secret');
  const { findings } = analyseToken(token, { now: NOW, includeAttacks: false });
  assert.equal(findings[0]?.id, 'JWT-WEAK-HMAC-SECRET');
  assert.equal(findings[0]?.severity, 'critical');
  const severities = findings.map((entry) => entry.severity);
  assert.deepEqual(severities, [...severities].sort((a, b) => {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    return order.indexOf(a) - order.indexOf(b);
  }));
});

test('a JWKS document supplies keys and labels them by kid', () => {
  const { publicKey, privateKey } = rsaPair();
  const jwks = JSON.stringify({ keys: [{ ...publicKeyToJwk(publicKey), kid: 'signing-2026-01' }] });
  const keys = loadKeysFromText(jwks, 'jwks.json', null);
  assert.equal(keys.length, 1);
  assert.equal(keys[0]?.source, 'jwks.json[kid=signing-2026-01]');

  const headerSegment = encodeJsonBase64url({ alg: 'RS256', kid: 'signing-2026-01' });
  const payloadSegment = encodeJsonBase64url(wellFormedClaims());
  const signature = signAsymmetric(describeAlgorithm('RS256'), privateKey, `${headerSegment}.${payloadSegment}`);
  const analysis = analyseToken(`${headerSegment}.${payloadSegment}.${encodeBase64url(signature)}`, {
    now: NOW,
    includeAttacks: false,
    keys,
  });
  assert.equal(analysis.structure.signatureVerification[0]?.source, 'jwks.json[kid=signing-2026-01]');
  assert.equal(analysis.structure.signatureVerification[0]?.valid, true);
});

test('a private key is accepted and its public part used, with a note', () => {
  const { privateKey } = rsaPair();
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const keys = loadKeysFromText(pem, 'signing.pem', Buffer.from(pem, 'utf8'));
  assert.equal(keys[0]?.derivedFromPrivate, true);
  const analysis = analyseToken(makeToken({ alg: 'RS256' }, wellFormedClaims(), Buffer.alloc(256)), {
    now: NOW,
    includeAttacks: false,
    keys,
  });
  assert.ok(analysis.notes.some((note) => note.includes('public part was derived')));
});

test('a non-JSON payload is reported and claim rules are skipped', () => {
  const analysis = analyseToken(makeToken({ alg: 'HS256' }, 'nested.token.here', Buffer.alloc(32)), {
    now: NOW,
    includeAttacks: false,
  });
  assert.equal(analysis.structure.payloadIsJsonObject, false);
  assert.ok(!ids(analysis.findings).includes('JWT-NO-EXP'));
  assert.ok(analysis.notes.some((note) => note.includes('not a JSON object')));
});

test('an unverifiable asymmetric token says that no key was supplied', () => {
  const analysis = analyseToken(makeToken({ alg: 'RS256' }, wellFormedClaims(), Buffer.alloc(256)), {
    now: NOW,
    includeAttacks: false,
  });
  assert.equal(analysis.structure.signatureVerification.length, 0);
  assert.ok(analysis.notes.some((note) => note.includes('No key was supplied')));
});

test('JWT-ALG-UNKNOWN also fires for a case variant of a real algorithm', () => {
  const analysis = analyseToken(makeToken({ alg: 'hs256' }, wellFormedClaims(), Buffer.alloc(32)), {
    now: NOW,
    includeAttacks: false,
  });
  const hit = finding(analysis.findings, 'JWT-ALG-UNKNOWN');
  assert.equal(hit.evidence['caseVariantOf'], 'HS256');
  assert.equal(hit.evidence['inferredFamily'], 'hmac');
  assert.equal(analysis.structure.algorithm.registered, false);
  // The lenient dispatch is assumed for length purposes, so a 32-byte
  // signature is still the right length and raises nothing further.
  assert.ok(!ids(analysis.findings).includes('JWT-SIG-LENGTH'));

  const registered = analyseToken(makeToken({ alg: 'HS256' }, wellFormedClaims(), Buffer.alloc(32)), {
    now: NOW,
    includeAttacks: false,
  });
  assert.ok(!ids(registered.findings).includes('JWT-ALG-UNKNOWN'));
});

test('JWT-ALG-UNKNOWN stands aside for a case variant of none', () => {
  const analysis = analyseToken(makeToken({ alg: 'NONE' }, wellFormedClaims()), {
    now: NOW,
    includeAttacks: false,
  });
  assert.ok(ids(analysis.findings).includes('JWT-ALG-NONE-VARIANT'));
  assert.ok(!ids(analysis.findings).includes('JWT-ALG-UNKNOWN'));
});

test('a supplied key that does not verify the token is not treated as measured', () => {
  // A 1024-bit signature with a 2048-bit key supplied: the key cannot be the
  // one that signed this token, so the key size must not be reported as fact.
  const { publicKey } = rsaPair();
  const pem = spkiPem(publicKey);
  const analysis = analyseToken(makeToken({ alg: 'RS256' }, wellFormedClaims(), Buffer.alloc(128)), {
    now: NOW,
    includeAttacks: false,
    keys: loadKeysFromText(pem, 'issuer-public.pem', Buffer.from(pem, 'utf8')),
  });
  const hit = finding(analysis.findings, 'JWT-RSA-SMALL-KEY');
  assert.equal(hit.confirmed, false);
  assert.match(String(hit.evidence['source']), /inferred/);
  assert.deepEqual(
    analysis.structure.signatureVerification.map((result) => result.valid),
    [false],
  );
});

test('JWT-KID-TRAVERSAL catches a percent-encoded path separator', () => {
  // Both patterns required a *literal* `/` or `\`, and a verifier that uses
  // `kid` to locate a key file generally decodes it first. So
  // `..%2fetc%2fpasswd` matched neither TRAVERSAL nor PATH_SHAPED and produced
  // no kid finding at all. The `%2e%2e` clause covered the mirror case --
  // encoded dots, literal slash -- which is how the gap stayed hidden: one
  // encoding of the pair was handled and the other was not.
  for (const kid of [
    '..%2fetc%2fpasswd',
    '..%2f..%2fetc%2fshadow',
    '..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts',
    '%2e%2e%2fetc%2fpasswd',
    '..%2Fetc%2Fpasswd',
    'keys%2e%2e%2fsigning',
    '../etc/passwd',
  ]) {
    const analysis = analyseToken(
      makeToken({ alg: 'HS256', kid }, wellFormedClaims(), Buffer.alloc(32)),
      { now: NOW, includeAttacks: false },
    );
    assert.ok(ids(analysis.findings).includes('JWT-KID-TRAVERSAL'), kid);
  }
});

test('a kid that is a plain path is still the lower JWT-KID-PATH', () => {
  // The traversal rule widening must not swallow the path rule: a kid that
  // names a file without climbing out of its directory is a weaker finding and
  // has to stay one.
  for (const kid of ['keys/signing.pem', 'etc%2fkeys%2fsigning.pem']) {
    const analysis = analyseToken(
      makeToken({ alg: 'HS256', kid }, wellFormedClaims(), Buffer.alloc(32)),
      { now: NOW, includeAttacks: false },
    );
    const found = ids(analysis.findings);
    assert.ok(found.includes('JWT-KID-PATH'), kid);
    assert.ok(!found.includes('JWT-KID-TRAVERSAL'), kid);
  }
});

test('an ordinary kid reports nothing about paths', () => {
  for (const kid of ['prod-key-2026', 'rsa-2048-a', 'key_1', '2026-10-rotation']) {
    const analysis = analyseToken(
      makeToken({ alg: 'HS256', kid }, wellFormedClaims(), Buffer.alloc(32)),
      { now: NOW, includeAttacks: false },
    );
    const found = ids(analysis.findings);
    assert.ok(!found.includes('JWT-KID-TRAVERSAL'), kid);
    assert.ok(!found.includes('JWT-KID-PATH'), kid);
  }
});

test('a lone percent in a kid does not throw', () => {
  // `kid` is attacker input and a bare `%` is a legal thing for it to contain;
  // decodeURIComponent would throw on it, which is why only the separator
  // escapes are decoded.
  for (const kid of ['100%', '%', '%zz', '%2', 'a%%2fb']) {
    assert.doesNotThrow(() =>
      analyseToken(makeToken({ alg: 'HS256', kid }, wellFormedClaims(), Buffer.alloc(32)), {
        now: NOW,
        includeAttacks: false,
      }),
    );
  }
});
