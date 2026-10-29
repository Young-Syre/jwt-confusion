import { decodeBase64urlLenient, type Base64urlIssue } from './base64url.js';
import type { EncodingIssueReport } from './types.js';

export type ParseFailureReason =
  | 'empty-input'
  | 'segment-count'
  | 'jwe-detected'
  | 'header-not-json'
  | 'header-not-object';

export class JwtParseError extends Error {
  constructor(
    message: string,
    readonly reason: ParseFailureReason,
  ) {
    super(message);
    this.name = 'JwtParseError';
  }
}

export interface DecodedToken {
  readonly raw: string;
  readonly segmentCount: number;
  readonly segments: {
    /** The segments exactly as presented, which is what a signature covers. */
    readonly header: string;
    readonly payload: string;
    readonly signature: string;
  };
  /** `header.payload`, verbatim. Re-encoding this would invalidate a signature. */
  readonly signingInput: string;
  readonly header: Readonly<Record<string, unknown>>;
  readonly payload: Readonly<Record<string, unknown>> | null;
  readonly payloadIsJsonObject: boolean;
  /** The raw decoded payload bytes, available even when the payload is not JSON. */
  readonly payloadBytes: Buffer;
  readonly signature: Buffer;
  readonly encodingIssues: readonly EncodingIssueReport[];
}

function collect(
  segment: 'header' | 'payload' | 'signature',
  issues: readonly Base64urlIssue[],
  describe: (issue: Base64urlIssue) => string,
): EncodingIssueReport[] {
  return issues.map((issue) => ({ segment, issue, detail: describe(issue) }));
}

/**
 * Parse a compact JWS. Tolerant on purpose: a token that cannot be parsed
 * cannot be analysed, and the tokens worth analysing are frequently malformed.
 * Only four things are hard failures — no input, the wrong number of segments,
 * a JWE, and a header that is not a JSON object — because past any of those
 * there is nothing left to reason about.
 */
export function decodeToken(raw: string, describeIssue: (issue: Base64urlIssue) => string): DecodedToken {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    throw new JwtParseError('no token supplied', 'empty-input');
  }

  // A bearer prefix is the single most common copy-paste artefact.
  const token = trimmed.replace(/^Bearer\s+/i, '').trim();
  const parts = token.split('.');

  if (parts.length === 5) {
    throw new JwtParseError(
      'this is a JWE (five segments, an encrypted token); jwt-confusion analyses JWS (signed tokens)',
      'jwe-detected',
    );
  }
  if (parts.length < 2 || parts.length > 3) {
    throw new JwtParseError(
      `expected 2 or 3 dot-separated segments, found ${parts.length}`,
      'segment-count',
    );
  }

  const headerSegment = parts[0] ?? '';
  const payloadSegment = parts[1] ?? '';
  const signatureSegment = parts[2] ?? '';

  const headerDecode = decodeBase64urlLenient(headerSegment);
  let header: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(headerDecode.bytes.toString('utf8'));
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new JwtParseError('the JOSE header did not decode to a JSON object', 'header-not-object');
    }
    header = parsed as Record<string, unknown>;
  } catch (error) {
    if (error instanceof JwtParseError) throw error;
    throw new JwtParseError(
      `the JOSE header did not decode to JSON: ${(error as Error).message}`,
      'header-not-json',
    );
  }

  const payloadDecode = decodeBase64urlLenient(payloadSegment);
  let payload: Record<string, unknown> | null = null;
  let payloadIsJsonObject = false;
  try {
    const parsed: unknown = JSON.parse(payloadDecode.bytes.toString('utf8'));
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
      payload = parsed as Record<string, unknown>;
      payloadIsJsonObject = true;
    }
  } catch {
    // A JWS payload need not be JSON (RFC 7515 allows arbitrary octets, and
    // nested JWTs carry a string). Record it and carry on.
  }

  const signatureDecode = decodeBase64urlLenient(signatureSegment);

  return {
    raw: token,
    segmentCount: parts.length,
    segments: { header: headerSegment, payload: payloadSegment, signature: signatureSegment },
    signingInput: `${headerSegment}.${payloadSegment}`,
    header,
    payload,
    payloadIsJsonObject,
    payloadBytes: payloadDecode.bytes,
    signature: signatureDecode.bytes,
    encodingIssues: [
      ...collect('header', headerDecode.issues, describeIssue),
      ...collect('payload', payloadDecode.issues, describeIssue),
      ...collect('signature', signatureDecode.issues, describeIssue),
    ],
  };
}
