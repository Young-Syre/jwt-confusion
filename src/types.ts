/**
 * Shared vocabulary for the analyser.
 *
 * Two fields in `Finding` carry most of the weight and are worth reading
 * before anything else:
 *
 *  - `severity` is the severity of the *verifier weakness* the finding points
 *    at, not of the token. A token with no `exp` is not itself dangerous; a
 *    verifier that will accept it forever is.
 *  - `confirmed` separates the two kinds of claim this tool makes. A confirmed
 *    finding was established with a cryptographic operation performed locally
 *    (a MAC that matched, a signature that verified). An unconfirmed finding is
 *    an observation about the token's shape which *implies* something about the
 *    verifier that cannot be established without sending a request. Reports
 *    built on unconfirmed findings need a server response to stand up.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Ascending order, so a higher index is a more severe finding. */
export const SEVERITY_ORDER: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

export type AlgorithmFamily = 'hmac' | 'rsa' | 'rsa-pss' | 'ecdsa' | 'eddsa' | 'none' | 'unknown';

export interface AlgorithmInfo {
  /** The `alg` header value exactly as it appeared, stringified if it was not a string. */
  readonly declared: string;
  readonly family: AlgorithmFamily;
  readonly hash: 'sha256' | 'sha384' | 'sha512' | null;
  /**
   * Exact expected signature length in bytes, or `null` when the length is a
   * function of the key size (RSA) and so cannot be predicted from the token.
   */
  readonly signatureBytes: number | null;
  /** Whether `declared` is an exact match for a JWS algorithm name. */
  readonly registered: boolean;
  /**
   * Set when `declared` differs from a registered name only by case, e.g.
   * `hs256` or `None`. Lenient verifiers that upper-case or lower-case the
   * header before dispatching will treat these as the registered algorithm.
   */
  readonly caseVariantOf: string | null;
}

export type EvidenceValue = string | number | boolean | null | undefined | readonly string[];

export interface Finding {
  readonly id: string;
  readonly name: string;
  readonly severity: Severity;
  readonly confirmed: boolean;
  /** Why this matters to the verifier, in one or two sentences. */
  readonly rationale: string;
  readonly evidence: Readonly<Record<string, EvidenceValue>>;
}

export interface ClaimPresence {
  readonly claim: string;
  readonly present: boolean;
  /** A short rendering of the value, or `null` when the claim is absent. */
  readonly rendered: string | null;
}

export interface VerificationResult {
  /** Where the key came from, e.g. `public-key.pem` or `jwks[kid=signing-1]`. */
  readonly source: string;
  readonly valid: boolean;
  readonly detail: string;
}

export interface EncodingIssueReport {
  readonly segment: 'header' | 'payload' | 'signature';
  readonly issue: string;
  readonly detail: string;
}

export interface TokenStructure {
  readonly segmentCount: number;
  readonly algorithm: AlgorithmInfo;
  readonly header: Readonly<Record<string, unknown>>;
  readonly payload: Readonly<Record<string, unknown>> | null;
  readonly payloadIsJsonObject: boolean;
  readonly signatureBytes: number;
  /** Which of the key-locator headers (`kid`, `jku`, `x5u`, `jwk`, `x5c`) are present. */
  readonly keyLocatorHeaders: readonly string[];
  readonly claims: readonly ClaimPresence[];
  /** `exp - iat` where both are present, else `null`. */
  readonly lifetimeSeconds: number | null;
  /** `null` when the token carries no `exp`. */
  readonly expired: boolean | null;
  readonly encodingIssues: readonly EncodingIssueReport[];
  readonly signatureVerification: readonly VerificationResult[];
}

export interface AttackArtifact {
  readonly name: string;
  readonly description: string;
  readonly content: string;
}

export interface AttackCandidate {
  readonly id: string;
  readonly name: string;
  readonly rationale: string;
  /** A complete, well-formed compact JWS. */
  readonly token: string;
  readonly header: Readonly<Record<string, unknown>>;
  /** How this token was signed, in plain words. */
  readonly signing: string;
  /**
   * What was checked locally about this token after generating it, or `null`
   * when nothing beyond its structure could be checked.
   */
  readonly verified: string | null;
  /** Anything the tester must do in addition to presenting the token. */
  readonly prerequisites: readonly string[];
  readonly artifacts: readonly AttackArtifact[];
}

export interface Analysis {
  readonly tool: string;
  readonly version: string;
  readonly analysedAt: string;
  readonly structure: TokenStructure;
  readonly findings: readonly Finding[];
  readonly attacks: readonly AttackCandidate[];
  /** Operator-facing remarks that are not findings: skipped checks, caveats. */
  readonly notes: readonly string[];
}
