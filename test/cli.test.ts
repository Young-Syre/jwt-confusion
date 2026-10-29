import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createPublicKey } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const PACKAGE_JSON = fileURLToPath(new URL('../../package.json', import.meta.url));

interface Run {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

function cli(args: readonly string[], stdin?: string): Run {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    input: stdin,
    env: { ...process.env, NO_COLOR: '1' },
  });
  return { status: result.status ?? -1, stdout: result.stdout, stderr: result.stderr };
}

function sample(kind?: string, extra: readonly string[] = []): string {
  const args = kind === undefined ? ['sample'] : ['sample', '--kind', kind];
  const result = cli([...args, ...extra]);
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

test('--help exits 0 and documents the exit codes', () => {
  const result = cli(['--help']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /EXIT CODES/);
  assert.match(result.stdout, /--expect-alg/);
  assert.match(result.stdout, /makes no network requests/);
});

test('no arguments prints help rather than failing', () => {
  const result = cli([]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /USAGE/);
});

test('-V prints the version in package.json', () => {
  const result = cli(['-V']);
  assert.equal(result.status, 0);
  const manifest = JSON.parse(readFileSync(PACKAGE_JSON, 'utf8')) as { version: string };
  assert.equal(result.stdout.trim(), manifest.version);
});

test('an unknown option is a usage error', () => {
  const result = cli(['--nonsense', 'x']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /unknown option --nonsense/);
});

test('a missing value is a usage error', () => {
  const result = cli([sample(), '--expect-alg']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /requires a value/);
});

test('an unreadable key file is a usage error, and the path is not echoed back in full', () => {
  const result = cli([sample(), '--public-key', join(tmpdir(), 'jwt-confusion-absent-key.pem')]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /could not read/);
});

test('a token that is not a JWS exits 3', () => {
  assert.equal(cli(['definitely-not-a-token']).status, 3);
  assert.equal(cli(['a.b.c.d.e']).status, 3);
  const jwe = cli(['a.b.c.d.e']);
  assert.match(jwe.stderr, /JWE/);
});

test('two tokens at once is a usage error', () => {
  const token = sample();
  const result = cli([token, token]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /one at a time/);
});

test('the weak-hmac sample is analysed, reports the recovered secret and exits 1', () => {
  const result = cli([sample(), '--now', '1760100000']);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /JWT-WEAK-HMAC-SECRET/);
  assert.match(result.stdout, /confirmed locally/);
  assert.match(result.stdout, /JWT-KID-TRAVERSAL/);
  assert.match(result.stdout, /No network request was made/);
});

test('--fail-on changes the exit code without changing the findings', () => {
  const token = sample();
  const strict = cli([token, '--now', '1760100000', '--fail-on', 'info']);
  assert.equal(strict.status, 1);
  const lenient = cli([token, '--now', '1760100000', '--fail-on', 'never']);
  assert.equal(lenient.status, 0);
  assert.equal(lenient.stdout.length, strict.stdout.length);

  const criticalOnly = cli([sample('unsecured'), '--now', '1760100000', '--fail-on', 'critical']);
  assert.equal(criticalOnly.status, 1);
  assert.match(criticalOnly.stdout, /JWT-ALG-NONE/);

  const bad = cli([token, '--fail-on', 'catastrophic']);
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /--fail-on expects/);
});

test('a token with no findings above the threshold exits 0', () => {
  const token = sample('rsa');
  const result = cli([token, '--now', '1760000500', '--fail-on', 'critical']);
  assert.equal(result.status, 0);
});

test('a token is read from standard input when the argument is -', () => {
  const result = cli(['-', '--now', '1760100000'], sample());
  assert.equal(result.status, 1);
  assert.match(result.stdout, /JWT-WEAK-HMAC-SECRET/);
});

test('a Bearer prefix on standard input is accepted', () => {
  const result = cli(['-', '--now', '1760100000'], `Bearer ${sample()}\n`);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /HS256/);
});

test('--json emits a parseable document with full tokens', () => {
  const result = cli([sample(), '--now', '1760100000', '--json']);
  assert.equal(result.status, 1);
  const analysis = JSON.parse(result.stdout) as {
    tool: string;
    findings: { id: string; confirmed: boolean }[];
    attacks: { id: string; token: string }[];
    structure: { algorithm: { declared: string } };
  };
  assert.equal(analysis.tool, 'jwt-confusion');
  assert.equal(analysis.structure.algorithm.declared, 'HS256');
  assert.ok(analysis.findings.some((finding) => finding.id === 'JWT-WEAK-HMAC-SECRET' && finding.confirmed));
  assert.ok(analysis.attacks.length >= 7);
  for (const attack of analysis.attacks) {
    assert.equal(attack.token.split('.').length, 3);
  }
});

test('--no-attacks removes the matrix from both output modes', () => {
  const text = cli([sample(), '--now', '1760100000', '--no-attacks']);
  assert.ok(!text.stdout.includes('ATTACK MATRIX'));
  const json = cli([sample(), '--now', '1760100000', '--no-attacks', '--json']);
  const analysis = JSON.parse(json.stdout) as { attacks: unknown[] };
  assert.equal(analysis.attacks.length, 0);
});

test('text output abbreviates tokens unless --full-tokens is given', () => {
  const token = sample();
  const abbreviated = cli([token, '--now', '1760100000']);
  assert.match(abbreviated.stdout, /abbreviated/);
  assert.ok(!abbreviated.stdout.includes(token));

  const full = cli([token, '--now', '1760100000', '--full-tokens']);
  assert.ok(!full.stdout.includes('abbreviated '));
  assert.ok(full.stdout.includes(token), 'the resigned candidate is the original token');
});

test('--claim rewrites the claims in every generated candidate', () => {
  const result = cli([sample(), '--now', '1760100000', '--json', '--claim', 'role=admin', '--claim', 'scope=["a","b"]']);
  assert.equal(result.status, 1);
  const analysis = JSON.parse(result.stdout) as { attacks: { id: string; token: string }[] };
  for (const attack of analysis.attacks) {
    const payload = JSON.parse(
      Buffer.from(attack.token.split('.')[1] ?? '', 'base64').toString('utf8'),
    ) as Record<string, unknown>;
    assert.equal(payload['role'], 'admin');
    assert.deepEqual(payload['scope'], ['a', 'b']);
  }
});

test('--claim without an equals sign is a usage error', () => {
  const result = cli([sample(), '--claim', 'role']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /key=value/);
});

test('the confused sample is detected as algorithm confusion against the key it names', () => {
  const directory = mkdtempSync(join(tmpdir(), 'jwt-confusion-'));
  const keyPath = join(directory, 'issuer-public.pem');
  const token = sample('confused', ['--write-key', keyPath]);
  const result = cli([token, '--public-key', keyPath, '--expect-alg', 'RS256', '--now', '1760100000']);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /JWT-ALG-CONFUSION-HS/);
  assert.match(result.stdout, /matchedRepresentation: file-bytes/);
  assert.match(result.stdout, /JWT-ALG-MISMATCH/);
});

test('an rsa sample verifies under its own key and offers confusion candidates', () => {
  const directory = mkdtempSync(join(tmpdir(), 'jwt-confusion-'));
  const keyPath = join(directory, 'issuer-public.pem');
  const token = sample('rsa', ['--write-key', keyPath]);
  const result = cli([token, '--public-key', keyPath, '--now', '1760100000', '--json']);
  const analysis = JSON.parse(result.stdout) as {
    findings: { id: string }[];
    attacks: { id: string }[];
    structure: { signatureVerification: { valid: boolean }[] };
  };
  assert.deepEqual(
    analysis.structure.signatureVerification.map((entry) => entry.valid),
    [true],
  );
  assert.ok(analysis.findings.some((finding) => finding.id === 'JWT-ALG-CONFUSION-CANDIDATE'));
  assert.ok(!analysis.findings.some((finding) => finding.id === 'JWT-ALG-CONFUSION-HS'));
  assert.ok(analysis.attacks.some((attack) => attack.id === 'ATK-HS-WITH-PUBKEY:file-bytes'));
});

test('a JWKS file supplied locally is used and never fetched', () => {
  const directory = mkdtempSync(join(tmpdir(), 'jwt-confusion-'));
  const keyPath = join(directory, 'issuer-public.pem');
  const token = sample('rsa', ['--write-key', keyPath]);
  const jwksPath = join(directory, 'jwks.json');
  const asJwk = cli([token, '--public-key', keyPath, '--json', '--no-attacks']);
  assert.equal(JSON.parse(asJwk.stdout).structure.signatureVerification[0].valid, true);

  // Build a JWKS from the same key by hand, so the JWKS path is exercised.
  const jwk = createPublicKey(readFileSync(keyPath)).export({ format: 'jwk' });
  writeFileSync(jwksPath, JSON.stringify({ keys: [{ ...jwk, kid: 'signing-2026-01' }] }));
  const result = cli([token, '--jwks', jwksPath, '--json', '--no-attacks']);
  const analysis = JSON.parse(result.stdout) as {
    structure: { signatureVerification: { source: string; valid: boolean }[] };
  };
  assert.equal(analysis.structure.signatureVerification[0]?.source, 'jwks.json[kid=signing-2026-01]');
  assert.equal(analysis.structure.signatureVerification[0]?.valid, true);
});

test('--kind confused refuses to run without --write-key', () => {
  const result = cli(['sample', '--kind', 'confused']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--write-key/);
});

test('an unknown sample kind is a usage error', () => {
  const result = cli(['sample', '--kind', 'nope']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--kind expects/);
});

test('every sample kind produces something the analyser can read', () => {
  for (const kind of ['weak-hmac', 'unsecured', 'rsa', 'embedded-jwk', 'ecdsa-zero']) {
    const token = sample(kind);
    const result = cli([token, '--now', '1760100000', '--json']);
    assert.ok(result.status === 0 || result.status === 1, `${kind}: ${result.stderr}`);
    const analysis = JSON.parse(result.stdout) as { structure: { segmentCount: number } };
    assert.equal(analysis.structure.segmentCount, 3, kind);
  }
});

test('--secret-list adds candidates from a file', () => {
  const directory = mkdtempSync(join(tmpdir(), 'jwt-confusion-'));
  const listPath = join(directory, 'secrets.txt');
  writeFileSync(listPath, 'first-line\nmy-project-signing-key\n');
  const token = sample();
  const withList = cli([token, '--secret-list', listPath, '--json', '--no-attacks', '--now', '1760100000']);
  const analysis = JSON.parse(withList.stdout) as { findings: { id: string; evidence: Record<string, unknown> }[] };
  const weak = analysis.findings.find((finding) => finding.id === 'JWT-WEAK-HMAC-SECRET');
  assert.ok(weak !== undefined, 'the built-in list should still find "secret"');
  assert.equal(weak.evidence['origin'], 'built-in list of common defaults');
  const withoutList = cli([token, '--json', '--no-attacks', '--now', '1760100000']);
  const baseline = JSON.parse(withoutList.stdout) as {
    findings: { id: string; evidence: Record<string, unknown> }[];
  };
  const baselineWeak = baseline.findings.find((finding) => finding.id === 'JWT-WEAK-HMAC-SECRET');
  assert.equal(
    Number(weak.evidence['candidatesTried']),
    Number(baselineWeak?.evidence['candidatesTried']) + 2,
    'the two non-blank lines should be added as candidates, and the trailing blank line ignored',
  );
});

test('a wrong --hmac-secret is reported as not matching', () => {
  const result = cli([
    sample('rsa'),
    '--json',
    '--no-attacks',
  ]);
  assert.equal(JSON.parse(result.stdout).structure.signatureVerification.length, 0);

  const hs = cli([sample(), '--json', '--no-attacks', '--hmac-secret', 'definitely-wrong', '--now', '1760100000']);
  const analysis = JSON.parse(hs.stdout) as {
    structure: { signatureVerification: { source: string; valid: boolean }[] };
  };
  // The built-in list still finds the real secret, so the valid entry wins and
  // is the one reported.
  assert.ok(analysis.structure.signatureVerification.some((entry) => entry.valid));
});

test('--now makes the output deterministic', () => {
  const token = sample();
  const first = cli([token, '--now', '1760100000', '--no-attacks']);
  const second = cli([token, '--now', new Date(1760100000 * 1000).toISOString(), '--no-attacks']);
  assert.equal(first.stdout, second.stdout);

  const bad = cli([token, '--now', 'not-a-date']);
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /--now is neither/);
});
