export { analyseToken, highestSeverityRank, type AnalyseOptions } from './analyse.js';
export { describeAlgorithm, isNoneVariant, REGISTERED_ALGORITHMS } from './algorithms.js';
export {
  Base64urlError,
  decodeBase64urlLenient,
  decodeBase64urlStrict,
  describeIssue,
  encodeBase64url,
  encodeJsonBase64url,
  isCanonicalBase64url,
  type Base64urlIssue,
  type LenientDecode,
} from './base64url.js';
export {
  bytesEqual,
  generateRsaKeyPair,
  hmac,
  hmacKeyRepresentations,
  jwkToPublicKey,
  loadKeysFromText,
  publicKeyToJwk,
  signAsymmetric,
  verifySignature,
  type KeyRepresentation,
  type LoadedKey,
} from './crypto.js';
export { WEAK_SECRETS } from './data/weak-secrets.js';
export { decodeToken, JwtParseError, type DecodedToken, type ParseFailureReason } from './decode.js';
export { gatherEvidence, type CryptoEvidence, type EvidenceInputs } from './evidence.js';
export { generateAttacks, type AttackInputs } from './attacks.js';
export { RULE_IDS, RULES, runRules, type Rule, type RuleContext } from './rules.js';
export { renderJson, renderText, type RenderOptions } from './report.js';
export { TOOL_NAME, VERSION } from './version.js';
export type {
  AlgorithmFamily,
  AlgorithmInfo,
  Analysis,
  AttackArtifact,
  AttackCandidate,
  ClaimPresence,
  EncodingIssueReport,
  EvidenceValue,
  Finding,
  Severity,
  TokenStructure,
  VerificationResult,
} from './types.js';
export { SEVERITY_ORDER, severityRank } from './types.js';
