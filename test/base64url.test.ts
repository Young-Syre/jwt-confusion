import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  Base64urlError,
  decodeBase64urlLenient,
  decodeBase64urlStrict,
  encodeBase64url,
  encodeJsonBase64url,
  isCanonicalBase64url,
} from '../src/base64url.js';

test('encodes the RFC 4648 test vectors without padding', () => {
  assert.equal(encodeBase64url(''), '');
  assert.equal(encodeBase64url('f'), 'Zg');
  assert.equal(encodeBase64url('fo'), 'Zm8');
  assert.equal(encodeBase64url('foo'), 'Zm9v');
  assert.equal(encodeBase64url('foob'), 'Zm9vYg');
  assert.equal(encodeBase64url('fooba'), 'Zm9vYmE');
  assert.equal(encodeBase64url('foobar'), 'Zm9vYmFy');
});

test('encodes with the URL-safe alphabet', () => {
  const encoded = encodeBase64url(Buffer.from([0xfb, 0xff]));
  assert.equal(encoded, '-_8');
  assert.ok(!encoded.includes('+'));
  assert.ok(!encoded.includes('/'));
  assert.ok(!encoded.includes('='));
});

test('encodeJsonBase64url round-trips an object', () => {
  const segment = encodeJsonBase64url({ alg: 'HS256', typ: 'JWT' });
  assert.deepEqual(JSON.parse(decodeBase64urlStrict(segment).toString('utf8')), {
    alg: 'HS256',
    typ: 'JWT',
  });
});

test('strict decoding accepts canonical input of every residue length', () => {
  assert.equal(decodeBase64urlStrict('').length, 0);
  assert.equal(decodeBase64urlStrict('Zg').toString('utf8'), 'f');
  assert.equal(decodeBase64urlStrict('Zm8').toString('utf8'), 'fo');
  assert.equal(decodeBase64urlStrict('Zm9v').toString('utf8'), 'foo');
  assert.equal(decodeBase64urlStrict('-_8').toString('hex'), 'fbff');
});

test('strict decoding rejects padding', () => {
  assert.throws(
    () => decodeBase64urlStrict('Zg=='),
    (error: unknown) => error instanceof Base64urlError && error.issue === 'padding-present',
  );
});

test('strict decoding rejects the standard base64 alphabet', () => {
  assert.throws(
    () => decodeBase64urlStrict('+/8'),
    (error: unknown) => error instanceof Base64urlError && error.issue === 'standard-alphabet',
  );
});

test('strict decoding rejects whitespace', () => {
  assert.throws(
    () => decodeBase64urlStrict('Zm 9v'),
    (error: unknown) => error instanceof Base64urlError && error.issue === 'whitespace',
  );
});

test('strict decoding rejects characters outside the alphabet', () => {
  assert.throws(
    () => decodeBase64urlStrict('Zm9v!!'),
    (error: unknown) => error instanceof Base64urlError && error.issue === 'invalid-character',
  );
});

test('strict decoding rejects an orphaned character', () => {
  assert.throws(
    () => decodeBase64urlStrict('Zm9vZ'),
    (error: unknown) => error instanceof Base64urlError && error.issue === 'invalid-length',
  );
});

test('strict decoding rejects non-canonical trailing bits', () => {
  // `Zg` and `Zh` both decode to the single byte 0x66; only `Zg` is canonical.
  assert.equal(Buffer.from('Zh', 'base64').toString('hex'), '66');
  assert.equal(Buffer.from('Zg', 'base64').toString('hex'), '66');
  assert.throws(
    () => decodeBase64urlStrict('Zh'),
    (error: unknown) =>
      error instanceof Base64urlError && error.issue === 'non-canonical-trailing-bits',
  );
});

test('canonicality check agrees with the strict decoder', () => {
  assert.equal(isCanonicalBase64url('Zm9vYmFy'), true);
  assert.equal(isCanonicalBase64url('Zg'), true);
  assert.equal(isCanonicalBase64url(''), true);
  assert.equal(isCanonicalBase64url('Zh'), false);
  assert.equal(isCanonicalBase64url('Zg=='), false);
  assert.equal(isCanonicalBase64url('+/8'), false);
  assert.equal(isCanonicalBase64url('Zm9vZ'), false);
});

test('lenient decoding reports padding but still returns the bytes', () => {
  const result = decodeBase64urlLenient('Zm9v==');
  assert.equal(result.bytes.toString('utf8'), 'foo');
  assert.ok(result.issues.includes('padding-present'));
});

test('lenient decoding reports the standard alphabet and normalises it', () => {
  const result = decodeBase64urlLenient('+/8');
  assert.equal(result.bytes.toString('hex'), 'fbff');
  assert.deepEqual([...result.issues], ['standard-alphabet']);
});

test('lenient decoding reports whitespace and invalid characters', () => {
  const whitespace = decodeBase64urlLenient('Zm 9v');
  assert.equal(whitespace.bytes.toString('utf8'), 'foo');
  assert.ok(whitespace.issues.includes('whitespace'));

  const invalid = decodeBase64urlLenient('Zm9v$$$$');
  assert.ok(invalid.issues.includes('invalid-character'));
});

test('lenient decoding reports non-canonical trailing bits', () => {
  const result = decodeBase64urlLenient('Zh');
  assert.equal(result.bytes.toString('hex'), '66');
  assert.deepEqual([...result.issues], ['non-canonical-trailing-bits']);
});

test('lenient decoding of canonical input reports nothing', () => {
  const result = decodeBase64urlLenient('Zm9vYmFy');
  assert.equal(result.issues.length, 0);
  assert.equal(result.bytes.toString('utf8'), 'foobar');
});

test('lenient decoding drops an orphaned character and says so', () => {
  const result = decodeBase64urlLenient('Zm9vZ');
  assert.ok(result.issues.includes('invalid-length'));
  assert.equal(result.bytes.toString('utf8'), 'foo');
});
