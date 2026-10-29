import assert from 'node:assert/strict';
import { test } from 'node:test';

import { analyseToken } from '../src/analyse.js';
import { describeAlgorithm } from '../src/algorithms.js';
import { decodeBase64urlStrict, describeIssue, encodeBase64url, encodeJsonBase64url } from '../src/base64url.js';
import {
  bytesEqual,
  hmac,
  jwkToPublicKey,
  loadKeysFromText,
  signAsymmetric,
  verifySignature,
} from '../src/crypto.js';
import { decodeToken } from '../src/decode.js';
import { abbreviateToken } from '../src/report.js';
import type { AttackCandidate } from '../src/types.js';

import { makeToken, rsaPair, spkiPem, wellFormedClaims } from './keys.js';

const NOW = new Date(1760000000 * 1000);
const HS256 = describeAlgorithm('HS256');
const RS256 = describeAlgorithm('RS256');

/** The shape a secret scanner looks for; generated output must never show it. */
const JWT_SHAPE = new RegExp('eyJ[A-Za-z0-9_-]{30,}\\.[A-Za-z0-9_-]{30,}');

function candidate(attacks: readonly AttackCandidate[], id: string): AttackCandidate {
  const match = attacks.find((entry) => entry.id === id);
  assert.ok(match !== undefined, `expected candidate ${id}, got ${attacks.map((a) => a.id).join(', ')}`);
  return match;
}

function rsaToken(): { token: string; pem: string } {
  const { publicKey, privateKey } = rsaPair();
  const headerSegment = encodeJsonBase64url({ alg: 'RS256', typ: 'JWT', kid: 'signing-2026-01' });
  const payloadSegment = encodeJsonBase64url(wellFormedClaims());
  const signature = signAsymmetric(RS256, privateKey, `${headerSegment}.${payloadSegment}`);
  return {
    token: `${headerSegment}.${payloadSegment}.${encodeBase64url(signature)}`,
    pem: spkiPem(publicKey),
  };
}

test('every generated candidate is a parseable compact JWS', () => {
  const { token, pem } = rsaToken();
  const analysis = analyseToken(token, {
    now: NOW,
    keys: loadKeysFromText(pem, 'issuer-public.pem', Buffer.from(pem, 'utf8')),
  });
  assert.ok(analysis.attacks.length >= 8);
  for (const attack of analysis.attacks) {
    const decoded = decodeToken(attack.token, describeIssue);
    assert.equal(decoded.segmentCount, 3, `${attack.id} should have three segments`);
    assert.equal(decoded.encodingIssues.length, 0, `${attack.id} should be canonical base64url`);
    assert.deepEqual(decoded.header, attack.header, `${attack.id} header should match the reported header`);
    assert.ok(attack.rationale.length > 40, `${attack.id} should explain itself`);
  }
});

test('candidate ids are unique', () => {
  const { token, pem } = rsaToken();
  const { attacks } = analyseToken(token, {
    now: NOW,
    keys: loadKeysFromText(pem, 'issuer-public.pem', Buffer.from(pem, 'utf8')),
  });
  const seen = attacks.map((attack) => attack.id);
  assert.equal(new Set(seen).size, seen.length);
});

test('the unsecured candidates carry an empty signature and the right spelling', () => {
  const { attacks } = analyseToken(makeToken({ alg: 'HS256' }, wellFormedClaims(), Buffer.alloc(32)), {
    now: NOW,
  });
  const none = candidate(attacks, 'ATK-ALG-NONE');
  assert.equal(none.header['alg'], 'none');
  assert.ok(none.token.endsWith('.'));
  assert.equal(none.token.split('.').length, 3);

  const variant = candidate(attacks, 'ATK-ALG-NONE-VARIANT');
  assert.equal(variant.header['alg'], 'None');
  assert.ok(variant.token.endsWith('.'));
});

test('the stripped-signature candidate keeps the original header byte for byte', () => {
  const original = makeToken({ alg: 'HS256', kid: 'signing-2026-01' }, wellFormedClaims(), Buffer.alloc(32, 3));
  const { attacks } = analyseToken(original, { now: NOW });
  const stripped = candidate(attacks, 'ATK-SIG-STRIPPED');
  assert.equal(stripped.token.split('.')[0], original.split('.')[0]);
  assert.equal(stripped.token.split('.')[2], '');
});

test('no stripped-signature candidate is offered when there is nothing to strip', () => {
  const { attacks } = analyseToken(makeToken({ alg: 'none' }, wellFormedClaims()), { now: NOW });
  assert.ok(!attacks.some((attack) => attack.id === 'ATK-SIG-STRIPPED'));
});

test('the HS-with-public-key candidates verify as HMACs under the representation they name', () => {
  const { token, pem } = rsaToken();
  const keys = loadKeysFromText(pem, 'issuer-public.pem', Buffer.from(pem, 'utf8'));
  const { attacks } = analyseToken(token, { now: NOW, keys });

  const confusion = attacks.filter((attack) => attack.id.startsWith('ATK-HS-WITH-PUBKEY:'));
  assert.ok(confusion.length >= 3, 'expected several key representations');

  const fileBytes = candidate(attacks, 'ATK-HS-WITH-PUBKEY:file-bytes');
  assert.equal(fileBytes.header['alg'], 'HS256');
  const [header, payload, signature] = fileBytes.token.split('.');
  const recomputed = hmac(HS256, Buffer.from(pem, 'utf8'), `${header}.${payload}`);
  assert.ok(bytesEqual(recomputed, decodeBase64urlStrict(signature ?? '')));

  // And the analyser recognises its own forgery when fed back in.
  const roundTrip = analyseToken(fileBytes.token, { now: NOW, keys, includeAttacks: false });
  const confirmed = roundTrip.findings.find((finding) => finding.id === 'JWT-ALG-CONFUSION-HS');
  assert.ok(confirmed !== undefined);
  assert.equal(confirmed.confirmed, true);
  assert.equal(confirmed.evidence['matchedRepresentation'], 'file-bytes');
});

test('the SPKI-PEM representation differs from the file bytes and also verifies', () => {
  const { token } = rsaToken();
  const { publicKey } = rsaPair();
  // A file with no trailing newline, so file-bytes and spki-pem cannot coincide.
  const pemWithoutNewline = spkiPem(publicKey).replace(/\n+$/, '');
  const keys = loadKeysFromText(pemWithoutNewline, 'issuer-public.pem', Buffer.from(pemWithoutNewline, 'utf8'));
  const { attacks } = analyseToken(token, { now: NOW, keys });

  const spki = candidate(attacks, 'ATK-HS-WITH-PUBKEY:spki-pem');
  const [header, payload, signature] = spki.token.split('.');
  const recomputed = hmac(HS256, Buffer.from(spkiPem(publicKey), 'utf8'), `${header}.${payload}`);
  assert.ok(bytesEqual(recomputed, decodeBase64urlStrict(signature ?? '')));
  assert.notEqual(
    candidate(attacks, 'ATK-HS-WITH-PUBKEY:file-bytes').token,
    spki.token,
    'two representations must produce two different tokens',
  );
});

test('no confusion candidates are generated without a key', () => {
  const { token } = rsaToken();
  const { attacks } = analyseToken(token, { now: NOW });
  assert.ok(!attacks.some((attack) => attack.id.startsWith('ATK-HS-WITH-PUBKEY')));
});

test('the embedded-jwk candidate verifies under the key it carries', () => {
  const { attacks } = analyseToken(makeToken({ alg: 'HS256' }, wellFormedClaims(), Buffer.alloc(32)), {
    now: NOW,
  });
  const embedded = candidate(attacks, 'ATK-EMBEDDED-JWK');
  assert.equal(embedded.header['alg'], 'RS256');
  const jwk = embedded.header['jwk'];
  assert.ok(jwk !== undefined);
  const key = jwkToPublicKey(jwk);
  const [header, payload, signature] = embedded.token.split('.');
  assert.ok(
    verifySignature(RS256, key, `${header}.${payload}`, decodeBase64urlStrict(signature ?? '')),
    'the candidate must verify under its own embedded key',
  );
  assert.match(embedded.verified ?? '', /verified/);

  // And the analyser reports it as self-signed when fed back in.
  const roundTrip = analyseToken(embedded.token, { now: NOW, includeAttacks: false });
  assert.ok(roundTrip.findings.some((finding) => finding.id === 'JWT-JWK-SELF-SIGNED'));
});

test('the jku candidate ships a JWKS that actually verifies it, at the host asked for', () => {
  const { attacks } = analyseToken(makeToken({ alg: 'HS256' }, wellFormedClaims(), Buffer.alloc(32)), {
    now: NOW,
    attackerHost: 'collab.invalid',
  });
  const remote = candidate(attacks, 'ATK-JKU-REMOTE');
  assert.equal(remote.header['jku'], 'https://collab.invalid/.well-known/jwks.json');
  assert.equal(remote.artifacts.length, 1);

  const artifact = remote.artifacts[0];
  assert.ok(artifact !== undefined);
  assert.equal(artifact.name, 'jwks.json');
  const jwks = JSON.parse(artifact.content) as { keys: Record<string, unknown>[] };
  assert.equal(jwks.keys.length, 1);
  assert.equal(jwks.keys[0]?.['kid'], remote.header['kid']);

  const key = jwkToPublicKey(jwks.keys[0]);
  const [header, payload, signature] = remote.token.split('.');
  assert.ok(verifySignature(RS256, key, `${header}.${payload}`, decodeBase64urlStrict(signature ?? '')));
});

test('the default attacker host is a reserved example domain', () => {
  const { attacks } = analyseToken(makeToken({ alg: 'HS256' }, wellFormedClaims(), Buffer.alloc(32)), {
    now: NOW,
  });
  assert.match(String(candidate(attacks, 'ATK-JKU-REMOTE').header['jku']), /^https:\/\/attacker\.example\//);
});

test('the kid /dev/null candidate is a valid MAC under a zero-length key', () => {
  const { attacks } = analyseToken(makeToken({ alg: 'HS256' }, wellFormedClaims(), Buffer.alloc(32)), {
    now: NOW,
  });
  const devNull = candidate(attacks, 'ATK-KID-DEVNULL');
  assert.match(String(devNull.header['kid']), /\/dev\/null$/);
  const [header, payload, signature] = devNull.token.split('.');
  const recomputed = hmac(HS256, Buffer.alloc(0), `${header}.${payload}`);
  assert.ok(bytesEqual(recomputed, decodeBase64urlStrict(signature ?? '')));
});

test('the kid SQL candidate is a valid MAC under the literal it injects', () => {
  const { attacks } = analyseToken(makeToken({ alg: 'HS256' }, wellFormedClaims(), Buffer.alloc(32)), {
    now: NOW,
  });
  const sql = candidate(attacks, 'ATK-KID-SQLI');
  const kid = String(sql.header['kid']);
  assert.match(kid, /UNION SELECT/);
  const injected = kid.slice(kid.lastIndexOf("'") + 1);
  const [header, payload, signature] = sql.token.split('.');
  const recomputed = hmac(HS256, Buffer.from(injected, 'utf8'), `${header}.${payload}`);
  assert.ok(bytesEqual(recomputed, decodeBase64urlStrict(signature ?? '')));

  // And the analyser flags the candidate's own kid when fed back in.
  const roundTrip = analyseToken(sql.token, { now: NOW, includeAttacks: false });
  assert.ok(roundTrip.findings.some((finding) => finding.id === 'JWT-KID-SQLMETA'));
});

test('the ECDSA zero-signature candidate is offered only for ECDSA, with the right length', () => {
  const es256 = analyseToken(makeToken({ alg: 'ES256' }, wellFormedClaims(), Buffer.alloc(64, 1)), { now: NOW });
  const zero = candidate(es256.attacks, 'ATK-ECDSA-ZERO-SIG');
  const signature = decodeBase64urlStrict(zero.token.split('.')[2] ?? '');
  assert.equal(signature.length, 64);
  assert.ok(signature.every((byte) => byte === 0));

  const hs = analyseToken(makeToken({ alg: 'HS256' }, wellFormedClaims(), Buffer.alloc(32)), { now: NOW });
  assert.ok(!hs.attacks.some((attack) => attack.id === 'ATK-ECDSA-ZERO-SIG'));
});

test('the recovered-secret candidate is only offered once the secret is known', () => {
  const headerSegment = encodeJsonBase64url({ alg: 'HS256' });
  const payloadSegment = encodeJsonBase64url(wellFormedClaims());
  const mac = hmac(HS256, Buffer.from('changeme', 'utf8'), `${headerSegment}.${payloadSegment}`);
  const weak = `${headerSegment}.${payloadSegment}.${encodeBase64url(mac)}`;

  const { attacks } = analyseToken(weak, { now: NOW });
  const resigned = candidate(attacks, 'ATK-HS-RECOVERED-SECRET');
  const [header, payload, signature] = resigned.token.split('.');
  const recomputed = hmac(HS256, Buffer.from('changeme', 'utf8'), `${header}.${payload}`);
  assert.ok(bytesEqual(recomputed, decodeBase64urlStrict(signature ?? '')));
  assert.equal(resigned.token, weak, 'with no claim overrides the resigned token is the original');

  const strong = analyseToken(makeToken({ alg: 'HS256' }, wellFormedClaims(), Buffer.alloc(32, 5)), { now: NOW });
  assert.ok(!strong.attacks.some((attack) => attack.id === 'ATK-HS-RECOVERED-SECRET'));
});

test('without claim overrides the payload segment is reused verbatim', () => {
  const original = makeToken({ alg: 'HS256' }, wellFormedClaims(), Buffer.alloc(32));
  const originalPayload = original.split('.')[1];
  const { attacks } = analyseToken(original, { now: NOW });
  for (const attack of attacks) {
    assert.equal(attack.token.split('.')[1], originalPayload, `${attack.id} must not re-encode the payload`);
  }
});

test('claim overrides are applied to every candidate and reported as a prerequisite', () => {
  const original = makeToken({ alg: 'HS256' }, wellFormedClaims(), Buffer.alloc(32));
  const { attacks } = analyseToken(original, {
    now: NOW,
    claimOverrides: { role: 'admin', sub: 'user-1' },
  });
  for (const attack of attacks) {
    const payload = JSON.parse(
      decodeBase64urlStrict(attack.token.split('.')[1] ?? '').toString('utf8'),
    ) as Record<string, unknown>;
    assert.equal(payload['role'], 'admin', `${attack.id} should carry the override`);
    assert.equal(payload['sub'], 'user-1');
    assert.equal(payload['iss'], 'https://issuer.example', 'untouched claims should survive');
    assert.ok(attack.prerequisites.some((entry) => entry.includes('Claims rewritten')));
  }
});

test('claim overrides on a non-JSON payload are declined rather than guessed at', () => {
  const original = makeToken({ alg: 'HS256' }, 'not-json', Buffer.alloc(32));
  const { attacks } = analyseToken(original, { now: NOW, claimOverrides: { role: 'admin' } });
  const none = candidate(attacks, 'ATK-ALG-NONE');
  assert.equal(none.token.split('.')[1], original.split('.')[1]);
  assert.ok(none.prerequisites.some((entry) => entry.includes('ignored')));
});

test('generation can be switched off entirely', () => {
  const analysis = analyseToken(makeToken({ alg: 'HS256' }, wellFormedClaims(), Buffer.alloc(32)), {
    now: NOW,
    includeAttacks: false,
  });
  assert.equal(analysis.attacks.length, 0);
});

test('abbreviated tokens never take the shape a secret scanner matches', () => {
  const { token, pem } = rsaToken();
  const { attacks } = analyseToken(token, {
    now: NOW,
    keys: loadKeysFromText(pem, 'issuer-public.pem', Buffer.from(pem, 'utf8')),
  });
  assert.ok(attacks.length > 0);
  for (const attack of attacks) {
    assert.ok(JWT_SHAPE.test(attack.token), `${attack.id}: the whole token does match the shape`);
    assert.ok(
      !JWT_SHAPE.test(abbreviateToken(attack.token)),
      `${attack.id}: the abbreviated form must not match`,
    );
  }
});
