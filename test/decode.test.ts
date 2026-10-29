import assert from 'node:assert/strict';
import { test } from 'node:test';

import { describeIssue, encodeJsonBase64url } from '../src/base64url.js';
import { decodeToken, JwtParseError } from '../src/decode.js';

import { makeToken } from './keys.js';

const parse = (raw: string) => decodeToken(raw, describeIssue);

test('parses a three-segment token and preserves the signing input verbatim', () => {
  const token = makeToken({ alg: 'HS256', typ: 'JWT' }, { sub: 'a' }, Buffer.alloc(32, 7));
  const decoded = parse(token);
  assert.equal(decoded.segmentCount, 3);
  assert.equal(decoded.header['alg'], 'HS256');
  assert.deepEqual(decoded.payload, { sub: 'a' });
  assert.equal(decoded.signature.length, 32);
  assert.equal(decoded.signingInput, token.split('.').slice(0, 2).join('.'));
  assert.equal(`${decoded.signingInput}.${decoded.segments.signature}`, token);
});

test('strips a Bearer prefix and surrounding whitespace', () => {
  const token = makeToken({ alg: 'none' }, { sub: 'a' });
  const decoded = parse(`  Bearer   ${token}  `);
  assert.equal(decoded.raw, token);
  assert.equal(decoded.header['alg'], 'none');
});

test('accepts a two-segment token and records the segment count', () => {
  const header = encodeJsonBase64url({ alg: 'none' });
  const payload = encodeJsonBase64url({ sub: 'a' });
  const decoded = parse(`${header}.${payload}`);
  assert.equal(decoded.segmentCount, 2);
  assert.equal(decoded.signature.length, 0);
});

test('rejects a five-segment JWE with a specific reason', () => {
  assert.throws(
    () => parse('a.b.c.d.e'),
    (error: unknown) => error instanceof JwtParseError && error.reason === 'jwe-detected',
  );
});

test('rejects the wrong number of segments', () => {
  assert.throws(
    () => parse('notatoken'),
    (error: unknown) => error instanceof JwtParseError && error.reason === 'segment-count',
  );
  assert.throws(
    () => parse('a.b.c.d'),
    (error: unknown) => error instanceof JwtParseError && error.reason === 'segment-count',
  );
});

test('rejects empty input', () => {
  assert.throws(
    () => parse('   '),
    (error: unknown) => error instanceof JwtParseError && error.reason === 'empty-input',
  );
});

test('rejects a header that is not JSON', () => {
  assert.throws(
    () => parse('bm90anNvbg.e30.'),
    (error: unknown) => error instanceof JwtParseError && error.reason === 'header-not-json',
  );
});

test('rejects a header that is JSON but not an object', () => {
  const header = encodeJsonBase64url(['HS256']);
  assert.throws(
    () => parse(`${header}.e30.`),
    (error: unknown) => error instanceof JwtParseError && error.reason === 'header-not-object',
  );
});

test('tolerates a payload that is not a JSON object', () => {
  const token = makeToken({ alg: 'HS256' }, 'a.nested.token');
  const decoded = parse(token);
  assert.equal(decoded.payloadIsJsonObject, false);
  assert.equal(decoded.payload, null);
  assert.equal(decoded.payloadBytes.toString('utf8'), 'a.nested.token');
});

test('attributes encoding issues to the segment they came from', () => {
  const header = encodeJsonBase64url({ alg: 'HS256' });
  const payload = `${encodeJsonBase64url({ sub: 'a' })}==`;
  const decoded = parse(`${header}.${payload}.`);
  const payloadIssues = decoded.encodingIssues.filter((issue) => issue.segment === 'payload');
  assert.equal(payloadIssues.length, 1);
  assert.equal(payloadIssues[0]?.issue, 'padding-present');
  assert.match(payloadIssues[0]?.detail ?? '', /unpadded/);
  assert.equal(decoded.encodingIssues.filter((issue) => issue.segment === 'header').length, 0);
});
