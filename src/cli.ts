#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';

import { analyseToken } from './analyse.js';
import { describeAlgorithm } from './algorithms.js';
import { encodeBase64url, encodeJsonBase64url } from './base64url.js';
import {
  generateRsaKeyPair,
  hmac,
  loadKeysFromText,
  publicKeyToJwk,
  signAsymmetric,
  type LoadedKey,
} from './crypto.js';
import { JwtParseError } from './decode.js';
import { renderJson, renderText } from './report.js';
import { SEVERITY_ORDER, severityRank, type Severity } from './types.js';
import { TOOL_NAME, VERSION } from './version.js';

/**
 * Exit codes, which are part of the interface and are documented in the README:
 *
 *   0  analysed; nothing at or above the --fail-on threshold
 *   1  analysed; at least one finding at or above the threshold
 *   2  usage error — bad flag, missing argument, unreadable key file
 *   3  the input is not a parseable compact JWS
 */
const EXIT_OK = 0;
const EXIT_FINDINGS = 1;
const EXIT_USAGE = 2;
const EXIT_UNPARSEABLE = 3;

const SAMPLE_KINDS = ['weak-hmac', 'unsecured', 'rsa', 'confused', 'embedded-jwk', 'ecdsa-zero'] as const;
type SampleKind = (typeof SAMPLE_KINDS)[number];

const HELP = `${TOOL_NAME} ${VERSION} — offline JWT verifier-weakness analyser and attack-matrix generator

USAGE
  ${TOOL_NAME} [analyse] <token|-> [options]
  ${TOOL_NAME} sample [--kind <kind>] [--write-key <path>]

  A token of "-" is read from standard input. A leading "Bearer " is ignored.

ANALYSIS OPTIONS
  --expect-alg <alg>        The algorithm this issuer is supposed to use. Any
                            other value in the header is then a finding.
  --public-key <path>       PEM public key (a private key is accepted and its
                            public part derived). Enables signature
                            verification and the HS/RS confusion check.
  --jwks <path>             A local JWKS or bare JWK document. Never fetched.
  --hmac-secret <value>     A secret to test before the built-in list.
  --secret-list <path>      Extra candidate secrets, one per line. Blank
                            lines are ignored.
  --max-lifetime-days <n>   Threshold for the excessive-lifetime rule (30).
  --now <iso|epoch>         Clock to evaluate exp/nbf against, for repeatable
                            output.

ATTACK MATRIX OPTIONS
  --claim <key=value>       Rewrite a claim in every generated token. Repeatable.
                            The value is parsed as JSON when it parses, else
                            used as a string.
  --attacker-host <host>    Host used in generated jku candidates
                            (default: attacker.example, which does not resolve).
  --max-confusion-variants <n>
                            How many byte representations of a supplied public
                            key to emit confusion candidates for (default: 4).
                            Five to nine are derived depending on the key; the
                            report says how many.
  --no-attacks              Skip generation entirely.
  --full-tokens             Print generated tokens in full. The default
                            abbreviates them so output is safe to paste into a
                            report or an issue without tripping a secret
                            scanner.

OUTPUT OPTIONS
  --json                    Machine-readable output; always includes full tokens.
  --fail-on <severity>      Exit 1 when a finding of this severity or higher is
                            present. One of ${SEVERITY_ORDER.join(', ')}, or
                            "never" (default: high).
  --no-color, --no-colour   Disable colour. Colour is off automatically when
                            output is not a terminal, or when NO_COLOR is set.
  -h, --help                This text.
  -V, --version             Version only.

SAMPLE OPTIONS
  --kind <kind>             One of ${SAMPLE_KINDS.slice(0, 4).join(', ')},
                            ${SAMPLE_KINDS.slice(4).join(', ')} (default: weak-hmac).
  --write-key <path>        Write the matching public key as SPKI PEM. Required
                            by --kind confused, which signs with that file's
                            exact bytes.

EXIT CODES
  0  analysed, nothing at or above the threshold
  1  analysed, findings at or above the threshold
  2  usage error
  3  the input is not a parseable compact JWS

This tool makes no network requests. jku, x5u and URL-shaped kid values are
reported, never fetched.
`;

interface ParsedArgs {
  readonly command: 'analyse' | 'sample';
  readonly positional: readonly string[];
  readonly flags: ReadonlyMap<string, string[]>;
  readonly booleans: ReadonlySet<string>;
}

const VALUE_FLAGS: readonly string[] = [
  'expect-alg',
  'public-key',
  'jwks',
  'hmac-secret',
  'secret-list',
  'max-lifetime-days',
  'now',
  'claim',
  'attacker-host',
  'max-confusion-variants',
  'fail-on',
  'kind',
  'write-key',
];

const BOOLEAN_FLAGS: readonly string[] = [
  'json',
  'no-attacks',
  'full-tokens',
  'no-color',
  'no-colour',
  'help',
  'version',
];

class UsageError extends Error {}

function parseArgs(argv: readonly string[]): ParsedArgs {
  const flags = new Map<string, string[]>();
  const booleans = new Set<string>();
  const positional: string[] = [];

  let command: 'analyse' | 'sample' = 'analyse';
  let index = 0;
  if (argv[0] === 'sample') {
    command = 'sample';
    index = 1;
  } else if (argv[0] === 'analyse' || argv[0] === 'analyze') {
    index = 1;
  }

  for (; index < argv.length; index += 1) {
    const argument = argv[index] as string;
    if (argument === '-h') {
      booleans.add('help');
      continue;
    }
    if (argument === '-V') {
      booleans.add('version');
      continue;
    }
    if (argument === '-') {
      positional.push('-');
      continue;
    }
    if (!argument.startsWith('--')) {
      positional.push(argument);
      continue;
    }

    const body = argument.slice(2);
    const equals = body.indexOf('=');
    const name = equals === -1 ? body : body.slice(0, equals);
    const inlineValue = equals === -1 ? null : body.slice(equals + 1);

    if (BOOLEAN_FLAGS.includes(name)) {
      if (inlineValue !== null) throw new UsageError(`--${name} does not take a value`);
      booleans.add(name);
      continue;
    }
    if (!VALUE_FLAGS.includes(name)) {
      throw new UsageError(`unknown option --${name}`);
    }
    const value = inlineValue ?? argv[index + 1];
    if (value === undefined) throw new UsageError(`--${name} requires a value`);
    if (inlineValue === null) index += 1;
    const existing = flags.get(name);
    if (existing === undefined) flags.set(name, [value]);
    else existing.push(value);
  }

  return { command, positional, flags, booleans };
}

function single(args: ParsedArgs, name: string): string | null {
  const values = args.flags.get(name);
  if (values === undefined) return null;
  if (values.length > 1) throw new UsageError(`--${name} may only be given once`);
  return values[0] ?? null;
}

function readStdin(): string {
  try {
    return readFileSync(0, 'utf8');
  } catch (error) {
    throw new UsageError(`could not read the token from standard input: ${(error as Error).message}`);
  }
}

function parseNow(value: string | null): Date {
  if (value === null) return new Date();
  if (/^\d+$/.test(value)) {
    const seconds = Number.parseInt(value, 10);
    return new Date(seconds * 1000);
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new UsageError(`--now is neither an epoch-seconds integer nor a parseable date: ${value}`);
  }
  return parsed;
}

function parseClaims(values: readonly string[]): Record<string, unknown> {
  const claims: Record<string, unknown> = {};
  for (const entry of values) {
    const equals = entry.indexOf('=');
    if (equals <= 0) throw new UsageError(`--claim expects key=value, got ${JSON.stringify(entry)}`);
    const key = entry.slice(0, equals);
    const raw = entry.slice(equals + 1);
    try {
      claims[key] = JSON.parse(raw);
    } catch {
      claims[key] = raw;
    }
  }
  return claims;
}

function loadKeyFile(path: string): LoadedKey[] {
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch (error) {
    throw new UsageError(`could not read ${path}: ${(error as Error).message}`);
  }
  // The basename only, so that output never carries a local directory layout.
  const source = path.split(/[/\\]/).pop() ?? path;
  try {
    return loadKeysFromText(bytes.toString('utf8'), source, bytes);
  } catch (error) {
    throw new UsageError((error as Error).message);
  }
}

function parseFailOn(value: string | null): number {
  if (value === null) return severityRank('high');
  if (value === 'never') return Number.POSITIVE_INFINITY;
  if (!SEVERITY_ORDER.includes(value as Severity)) {
    throw new UsageError(`--fail-on expects one of ${SEVERITY_ORDER.join(', ')} or "never", got ${value}`);
  }
  return severityRank(value as Severity);
}

function colourEnabled(args: ParsedArgs): boolean {
  if (args.booleans.has('no-color') || args.booleans.has('no-colour')) return false;
  if (process.env['NO_COLOR'] !== undefined && process.env['NO_COLOR'] !== '') return false;
  return process.stdout.isTTY === true;
}

/**
 * Sample tokens, so that every example in the README can be reproduced without
 * the repository shipping a single token or key fixture. See the README section
 * "Why there are no key fixtures in this repo" for why that matters.
 */
function buildSample(kind: SampleKind, writeKeyPath: string | null): string {
  const payload = {
    sub: 'user-1042',
    name: 'Sample Subject',
    role: 'viewer',
    iat: 1760000000,
  };
  const payloadSegment = encodeJsonBase64url(payload);

  switch (kind) {
    case 'weak-hmac': {
      const header = { alg: 'HS256', typ: 'JWT', kid: '../../config/keys/signing.pem' };
      const headerSegment = encodeJsonBase64url(header);
      const signingInput = `${headerSegment}.${payloadSegment}`;
      const mac = hmac(describeAlgorithm('HS256'), Buffer.from('secret', 'utf8'), signingInput);
      return `${signingInput}.${encodeBase64url(mac)}`;
    }
    case 'unsecured': {
      const headerSegment = encodeJsonBase64url({ alg: 'none', typ: 'JWT' });
      return `${headerSegment}.${payloadSegment}.`;
    }
    case 'rsa':
    case 'confused': {
      const { publicKey, privateKey } = generateRsaKeyPair(2048);
      const pem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
      if (writeKeyPath === null) {
        if (kind === 'confused') {
          throw new UsageError('--kind confused requires --write-key: the signature is keyed with that file\'s exact bytes');
        }
      } else {
        writeFileSync(writeKeyPath, pem);
      }
      if (kind === 'rsa') {
        const headerSegment = encodeJsonBase64url({ alg: 'RS256', typ: 'JWT', kid: 'signing-2026-01' });
        const signingInput = `${headerSegment}.${payloadSegment}`;
        const signature = signAsymmetric(describeAlgorithm('RS256'), privateKey, signingInput);
        return `${signingInput}.${encodeBase64url(signature)}`;
      }
      // A token forged the way a successful algorithm-confusion attack forges
      // one: HS256, keyed with the exact bytes of the public key file.
      const headerSegment = encodeJsonBase64url({ alg: 'HS256', typ: 'JWT', kid: 'signing-2026-01' });
      const signingInput = `${headerSegment}.${payloadSegment}`;
      const mac = hmac(describeAlgorithm('HS256'), Buffer.from(pem, 'utf8'), signingInput);
      return `${signingInput}.${encodeBase64url(mac)}`;
    }
    case 'embedded-jwk': {
      const { publicKey, privateKey } = generateRsaKeyPair(2048);
      if (writeKeyPath !== null) {
        writeFileSync(writeKeyPath, publicKey.export({ type: 'spki', format: 'pem' }) as string);
      }
      const header = { alg: 'RS256', typ: 'JWT', jwk: publicKeyToJwk(publicKey) };
      const headerSegment = encodeJsonBase64url(header);
      const signingInput = `${headerSegment}.${payloadSegment}`;
      const signature = signAsymmetric(describeAlgorithm('RS256'), privateKey, signingInput);
      return `${signingInput}.${encodeBase64url(signature)}`;
    }
    case 'ecdsa-zero': {
      const headerSegment = encodeJsonBase64url({ alg: 'ES256', typ: 'JWT' });
      return `${headerSegment}.${payloadSegment}.${encodeBase64url(Buffer.alloc(64))}`;
    }
  }
}

function run(argv: readonly string[]): number {
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`${TOOL_NAME}: ${(error as Error).message}\n`);
    return EXIT_USAGE;
  }

  try {
    if (args.booleans.has('help') || (args.command === 'analyse' && args.positional.length === 0 && argv.length === 0)) {
      process.stdout.write(HELP);
      return EXIT_OK;
    }
    if (args.booleans.has('version')) {
      process.stdout.write(`${VERSION}\n`);
      return EXIT_OK;
    }

    if (args.command === 'sample') {
      const kind = (single(args, 'kind') ?? 'weak-hmac') as SampleKind;
      if (!SAMPLE_KINDS.includes(kind)) {
        throw new UsageError(`--kind expects one of ${SAMPLE_KINDS.join(', ')}, got ${kind}`);
      }
      process.stdout.write(`${buildSample(kind, single(args, 'write-key'))}\n`);
      return EXIT_OK;
    }

    if (args.positional.length === 0) {
      throw new UsageError('no token supplied; pass a token, or "-" to read one from standard input');
    }
    if (args.positional.length > 1) {
      throw new UsageError('more than one token supplied; analyse one at a time');
    }

    const rawToken = args.positional[0] === '-' ? readStdin() : (args.positional[0] as string);

    const keys: LoadedKey[] = [];
    const publicKeyPath = single(args, 'public-key');
    if (publicKeyPath !== null) keys.push(...loadKeyFile(publicKeyPath));
    const jwksPath = single(args, 'jwks');
    if (jwksPath !== null) keys.push(...loadKeyFile(jwksPath));

    const secretListPath = single(args, 'secret-list');
    let extraSecrets: string[] = [];
    if (secretListPath !== null) {
      try {
        // Blank lines are dropped rather than treated as the empty secret: the
        // empty secret is already in the built-in list, and crediting it to a
        // user-supplied file because that file ended with a newline would
        // misattribute the finding.
        extraSecrets = readFileSync(secretListPath, 'utf8')
          .split('\n')
          .map((line) => line.replace(/\r$/, ''))
          .filter((line) => line.length > 0);
      } catch (error) {
        throw new UsageError(`could not read ${secretListPath}: ${(error as Error).message}`);
      }
    }

    const maxLifetimeRaw = single(args, 'max-lifetime-days');
    const maxLifetimeDays = maxLifetimeRaw === null ? 30 : Number(maxLifetimeRaw);
    if (!Number.isFinite(maxLifetimeDays) || maxLifetimeDays < 0) {
      throw new UsageError(`--max-lifetime-days expects a non-negative number, got ${maxLifetimeRaw}`);
    }

    const variantsRaw = single(args, 'max-confusion-variants');
    const maxConfusionVariants = variantsRaw === null ? 4 : Number(variantsRaw);
    if (!Number.isInteger(maxConfusionVariants) || maxConfusionVariants < 0) {
      throw new UsageError(`--max-confusion-variants expects a non-negative integer, got ${variantsRaw}`);
    }

    const failOnRank = parseFailOn(single(args, 'fail-on'));
    const showAttacks = !args.booleans.has('no-attacks');

    const analysis = analyseToken(rawToken, {
      keys,
      hmacSecret: single(args, 'hmac-secret'),
      extraSecrets,
      expectAlg: single(args, 'expect-alg'),
      now: parseNow(single(args, 'now')),
      maxLifetimeDays,
      includeAttacks: showAttacks,
      attackerHost: single(args, 'attacker-host') ?? 'attacker.example',
      maxConfusionVariants: maxConfusionVariants,
      claimOverrides: parseClaims(args.flags.get('claim') ?? []),
    });

    if (args.booleans.has('json')) {
      process.stdout.write(renderJson(analysis, { showAttacks }));
    } else {
      process.stdout.write(
        renderText(analysis, {
          colour: colourEnabled(args),
          fullTokens: args.booleans.has('full-tokens'),
          showAttacks,
        }),
      );
    }

    const highest = analysis.findings.reduce(
      (rank, finding) => Math.max(rank, severityRank(finding.severity)),
      -1,
    );
    return highest >= failOnRank ? EXIT_FINDINGS : EXIT_OK;
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`${TOOL_NAME}: ${error.message}\n`);
      return EXIT_USAGE;
    }
    if (error instanceof JwtParseError) {
      process.stderr.write(`${TOOL_NAME}: ${error.message} (${error.reason})\n`);
      return EXIT_UNPARSEABLE;
    }
    process.stderr.write(`${TOOL_NAME}: ${(error as Error).message}\n`);
    return EXIT_USAGE;
  }
}

process.exitCode = run(process.argv.slice(2));
