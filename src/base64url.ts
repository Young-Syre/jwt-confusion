/**
 * Strict and lenient base64url, kept deliberately separate.
 *
 * RFC 7515 §2 defines base64url for JOSE as unpadded, using `-` and `_` in
 * place of `+` and `/`. Plenty of real verifiers reach for a tolerant decoder
 * instead — `Buffer.from(s, 'base64')` in Node, `base64.b64decode` with a
 * fix-up in Python — and a tolerant decoder accepts input that a strict one
 * rejects. That gap is exploitable: if the attacker can get the verifier to
 * accept a segment that is not canonical base64url, two encodings of the same
 * bytes reach two different pieces of code. A gateway that checks claims on one
 * encoding and an application that re-decodes the other disagree about the
 * token, and the signature covers the *bytes of the segment*, not the decoded
 * JSON, so re-encoding is a forgery while re-decoding is not.
 *
 * So the analyser decodes leniently — it has to, or it could not look at a
 * malformed token at all — and separately records every way in which the input
 * departed from canonical form.
 */

const BASE64URL_ALPHABET = /^[A-Za-z0-9_-]*$/;

export type Base64urlIssue =
  | 'padding-present'
  | 'standard-alphabet'
  | 'invalid-length'
  | 'non-canonical-trailing-bits'
  | 'whitespace'
  | 'invalid-character';

export interface LenientDecode {
  readonly bytes: Buffer;
  readonly issues: readonly Base64urlIssue[];
}

export class Base64urlError extends Error {
  constructor(
    message: string,
    readonly issue: Base64urlIssue,
  ) {
    super(message);
    this.name = 'Base64urlError';
  }
}

export function encodeBase64url(input: Uint8Array | string): string {
  const buffer = typeof input === 'string' ? Buffer.from(input, 'utf8') : Buffer.from(input);
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function encodeJsonBase64url(value: unknown): string {
  return encodeBase64url(JSON.stringify(value));
}

/**
 * True when `input` is the one and only canonical base64url encoding of the
 * bytes it decodes to. Catches both the obvious departures (padding, the
 * standard alphabet) and the subtle one: a final character whose unused
 * low-order bits are not zero. `QQ` and `QR` both decode to the single byte
 * 0x41, but only `QQ` is canonical.
 */
export function isCanonicalBase64url(input: string): boolean {
  if (!BASE64URL_ALPHABET.test(input)) return false;
  if (input.length % 4 === 1) return false;
  return encodeBase64url(Buffer.from(input, 'base64')) === input;
}

/**
 * Decode, rejecting anything that is not canonical base64url. This is the
 * decoder a verifier ought to use.
 */
export function decodeBase64urlStrict(input: string): Buffer {
  if (/\s/.test(input)) {
    throw new Base64urlError('contains whitespace', 'whitespace');
  }
  if (input.includes('=')) {
    throw new Base64urlError('contains `=` padding, which JOSE base64url omits', 'padding-present');
  }
  if (/[+/]/.test(input)) {
    throw new Base64urlError(
      'uses the standard base64 alphabet (`+` or `/`) rather than base64url (`-` or `_`)',
      'standard-alphabet',
    );
  }
  if (!BASE64URL_ALPHABET.test(input)) {
    throw new Base64urlError('contains characters outside the base64url alphabet', 'invalid-character');
  }
  if (input.length % 4 === 1) {
    throw new Base64urlError('length leaves a single orphaned character', 'invalid-length');
  }
  const bytes = Buffer.from(input, 'base64');
  if (encodeBase64url(bytes) !== input) {
    throw new Base64urlError(
      'final character carries non-zero unused bits, so this is not the canonical encoding of these bytes',
      'non-canonical-trailing-bits',
    );
  }
  return bytes;
}

/**
 * Decode whatever we are given, recording each departure from canonical form.
 * Never throws: an unanalysable token is less useful than an analysed
 * malformed one.
 */
export function decodeBase64urlLenient(input: string): LenientDecode {
  const issues: Base64urlIssue[] = [];
  let working = input;

  if (/\s/.test(working)) {
    issues.push('whitespace');
    working = working.replace(/\s+/g, '');
  }
  if (working.includes('=')) {
    issues.push('padding-present');
    working = working.replace(/=+$/, '').replace(/=/g, '');
  }
  if (/[+/]/.test(working)) {
    issues.push('standard-alphabet');
    working = working.replace(/\+/g, '-').replace(/\//g, '_');
  }
  if (!BASE64URL_ALPHABET.test(working)) {
    issues.push('invalid-character');
    working = working.replace(/[^A-Za-z0-9_-]/g, '');
  }
  if (working.length % 4 === 1) {
    issues.push('invalid-length');
    working = working.slice(0, -1);
  }

  const bytes = Buffer.from(working, 'base64');
  if (encodeBase64url(bytes) !== working) {
    issues.push('non-canonical-trailing-bits');
  }

  return { bytes, issues };
}

export function describeIssue(issue: Base64urlIssue): string {
  switch (issue) {
    case 'padding-present':
      return '`=` padding is present; JOSE base64url is unpadded';
    case 'standard-alphabet':
      return 'standard base64 characters (`+`, `/`) appear instead of `-` and `_`';
    case 'invalid-length':
      return 'segment length leaves an orphaned character and cannot be a whole number of bytes';
    case 'non-canonical-trailing-bits':
      return 'the final character carries non-zero unused bits, so the same bytes have a shorter canonical encoding';
    case 'whitespace':
      return 'segment contains whitespace';
    case 'invalid-character':
      return 'segment contains characters outside the base64url alphabet';
  }
}
