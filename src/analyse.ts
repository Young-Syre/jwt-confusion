import { describeAlgorithm } from './algorithms.js';
import { generateAttacks } from './attacks.js';
import { describeIssue } from './base64url.js';
import type { LoadedKey } from './crypto.js';
import { decodeToken } from './decode.js';
import { gatherEvidence } from './evidence.js';
import { runRules } from './rules.js';
import { severityRank, type Analysis, type ClaimPresence, type Finding, type TokenStructure } from './types.js';
import { TOOL_NAME, VERSION } from './version.js';

export interface AnalyseOptions {
  readonly keys?: readonly LoadedKey[];
  readonly hmacSecret?: string | null;
  readonly extraSecrets?: readonly string[];
  /** The algorithm the caller asserts this issuer uses, for the pinning check. */
  readonly expectAlg?: string | null;
  readonly now?: Date;
  readonly maxLifetimeDays?: number;
  readonly includeAttacks?: boolean;
  readonly attackerHost?: string;
  readonly claimOverrides?: Readonly<Record<string, unknown>>;
  readonly maxConfusionVariants?: number;
}

/** The registered claims whose presence is always reported, in RFC 7519 order. */
const REGISTERED_CLAIMS: readonly string[] = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];

const KEY_LOCATOR_HEADERS: readonly string[] = ['kid', 'jku', 'jwk', 'x5u', 'x5c', 'x5t', 'x5t#S256'];

const TIME_CLAIMS: readonly string[] = ['exp', 'nbf', 'iat'];

function renderClaim(name: string, value: unknown): string {
  if (TIME_CLAIMS.includes(name) && typeof value === 'number' && Number.isFinite(value)) {
    return `${value} (${new Date(value * 1000).toISOString()})`;
  }
  if (typeof value === 'string') return JSON.stringify(value);
  return JSON.stringify(value) ?? String(value);
}

function claimPresence(payload: Readonly<Record<string, unknown>> | null): ClaimPresence[] {
  return REGISTERED_CLAIMS.map((claim) => {
    const value = payload?.[claim];
    return {
      claim,
      present: value !== undefined,
      rendered: value === undefined ? null : renderClaim(claim, value),
    };
  });
}

function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = severityRank(b.severity) - severityRank(a.severity);
    if (bySeverity !== 0) return bySeverity;
    // Within a severity, confirmed findings first: they need no further proof.
    if (a.confirmed !== b.confirmed) return a.confirmed ? -1 : 1;
    return a.id.localeCompare(b.id);
  });
}

export function analyseToken(raw: string, options: AnalyseOptions = {}): Analysis {
  const now = options.now ?? new Date();
  const maxLifetimeDays = options.maxLifetimeDays ?? 30;
  const keys = options.keys ?? [];

  const token = decodeToken(raw, describeIssue);
  const algorithm = describeAlgorithm(token.header['alg']);

  const evidence = gatherEvidence(token, algorithm, {
    keys,
    hmacSecret: options.hmacSecret ?? null,
    extraSecrets: options.extraSecrets ?? [],
  });

  const findings = sortFindings(
    runRules({
      token,
      algorithm,
      evidence,
      now,
      expectAlg: options.expectAlg ?? null,
      maxLifetimeSeconds: Math.round(maxLifetimeDays * 86400),
      secretListSize: evidence.secretsTried,
    }),
  );

  const exp = token.payload?.['exp'];
  const iat = token.payload?.['iat'];
  const expSeconds = typeof exp === 'number' && Number.isFinite(exp) ? exp : null;
  const iatSeconds = typeof iat === 'number' && Number.isFinite(iat) ? iat : null;

  const structure: TokenStructure = {
    segmentCount: token.segmentCount,
    algorithm,
    header: token.header,
    payload: token.payload,
    payloadIsJsonObject: token.payloadIsJsonObject,
    signatureBytes: token.signature.length,
    keyLocatorHeaders: KEY_LOCATOR_HEADERS.filter((name) => token.header[name] !== undefined),
    claims: claimPresence(token.payload),
    lifetimeSeconds: expSeconds !== null && iatSeconds !== null ? expSeconds - iatSeconds : null,
    expired: expSeconds === null ? null : expSeconds <= Math.floor(now.getTime() / 1000),
    encodingIssues: token.encodingIssues,
    signatureVerification: evidence.verification,
  };

  const notes = [...evidence.notes];
  if (!token.payloadIsJsonObject) {
    notes.push(
      'The payload is not a JSON object, so no claim-level rule was applied. RFC 7515 permits an arbitrary payload; a nested JWT is the usual reason.',
    );
  }
  if (token.segmentCount === 2) {
    notes.push(
      'The token has two segments rather than three. A compact JWS always has three, with the signature segment left empty for an unsecured token.',
    );
  }
  if (keys.length === 0 && (algorithm.family === 'rsa' || algorithm.family === 'rsa-pss' || algorithm.family === 'ecdsa' || algorithm.family === 'eddsa')) {
    notes.push(
      'No key was supplied, so the signature was not verified and no algorithm-confusion candidates could be built. Pass --public-key or --jwks to enable both.',
    );
  }

  const attacks =
    options.includeAttacks === false
      ? []
      : generateAttacks({
          token,
          algorithm,
          evidence,
          keys,
          attackerHost: options.attackerHost ?? 'attacker.example',
          claimOverrides: options.claimOverrides ?? {},
          maxConfusionVariants: options.maxConfusionVariants ?? 4,
        });

  return {
    tool: TOOL_NAME,
    version: VERSION,
    analysedAt: now.toISOString(),
    structure,
    findings,
    attacks,
    notes,
  };
}

export function highestSeverityRank(findings: readonly Finding[]): number {
  return findings.reduce((highest, finding) => Math.max(highest, severityRank(finding.severity)), -1);
}
