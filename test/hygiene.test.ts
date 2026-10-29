import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { analyseToken } from '../src/analyse.js';
import { WEAK_SECRETS } from '../src/data/weak-secrets.js';
import { RULE_IDS } from '../src/rules.js';
import { VERSION } from '../src/version.js';

import { makeToken, rsaPair, spkiPem, wellFormedClaims } from './keys.js';
import { loadKeysFromText } from '../src/crypto.js';

/**
 * Checks on the repository itself rather than on the tool. Two of the claims in
 * the README are claims about this source tree, and a claim about a source tree
 * can be tested:
 *
 *  1. The tool makes no network requests. Nothing in `src/` imports a network
 *     module or calls a network API, and nothing shells out to a process that
 *     could make the request on its behalf.
 *  2. Nothing committed here is shaped like a credential. A repository about
 *     JWTs is the worst place to leave a JWT lying around, and secret scanners
 *     are right to block one.
 */
const REPO = fileURLToPath(new URL('../../', import.meta.url));

const SKIP_DIRECTORIES = new Set(['.git', 'node_modules', 'dist', '.github']);
const TEXT_EXTENSIONS = ['.ts', '.js', '.json', '.md', '.yml', '.yaml', '.txt', '.pem'];

function walk(directory: string, accumulated: string[] = []): string[] {
  for (const entry of readdirSync(directory)) {
    if (SKIP_DIRECTORIES.has(entry)) continue;
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) walk(path, accumulated);
    else accumulated.push(path);
  }
  return accumulated;
}

function sourceFiles(): string[] {
  return walk(join(REPO, 'src')).filter((path) => path.endsWith('.ts'));
}

function committedTextFiles(): string[] {
  const workflows = walk(join(REPO, '.github'));
  return [...walk(REPO), ...workflows].filter((path) =>
    TEXT_EXTENSIONS.some((extension) => path.endsWith(extension)),
  );
}

test('nothing in src imports a network module or shells out', () => {
  const forbidden: readonly { pattern: RegExp; why: string }[] = [
    { pattern: /from\s+'node:(http|https|http2|net|tls|dgram|dns)'/, why: 'network module import' },
    { pattern: /require\(\s*'(node:)?(http|https|http2|net|tls|dgram|dns)'\s*\)/, why: 'network module require' },
    { pattern: /from\s+'node:child_process'/, why: 'could shell out to a network client' },
    { pattern: /\bfetch\s*\(/, why: 'fetch call' },
    { pattern: /XMLHttpRequest|WebSocket|EventSource/, why: 'browser network API' },
    { pattern: /from\s+'(axios|undici|node-fetch|got|superagent|request)'/, why: 'HTTP client dependency' },
  ];

  const files = sourceFiles();
  assert.ok(files.length >= 10, 'expected the source tree to be found');
  for (const path of files) {
    const contents = readFileSync(path, 'utf8');
    for (const { pattern, why } of forbidden) {
      assert.ok(
        !pattern.test(contents),
        `${path.slice(REPO.length)} contains a ${why} matching ${pattern}`,
      );
    }
  }
});

test('the package declares no runtime dependencies', () => {
  const manifest = JSON.parse(readFileSync(join(REPO, 'package.json'), 'utf8')) as {
    version: string;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  assert.equal(manifest.dependencies, undefined);
  assert.deepEqual(Object.keys(manifest.devDependencies ?? {}).sort(), ['@types/node', 'typescript']);
  assert.equal(manifest.version, VERSION, 'src/version.ts must match package.json');
});

test('no committed file contains a credential-shaped literal', () => {
  // Assembled from fragments so that this file does not match its own checks.
  const patterns: readonly { label: string; pattern: RegExp }[] = [
    { label: 'PEM private key', pattern: new RegExp(`-----BEGIN [A-Z ]*PRIVATE${' '}KEY-----`) },
    { label: 'complete JWT', pattern: new RegExp('eyJ[A-Za-z0-9_-]{30,}\\.[A-Za-z0-9_-]{30,}') },
    { label: 'AWS access key id', pattern: new RegExp(`${'AKI'}A[0-9A-Z]{16}`) },
    { label: 'GitHub personal access token', pattern: new RegExp(`${'ghp'}_[0-9A-Za-z]{36}`) },
    { label: 'Stripe live key', pattern: new RegExp(`${'sk_li'}ve_[0-9A-Za-z]{20,}`) },
    { label: 'Google API key', pattern: new RegExp(`${'AIz'}a[0-9A-Za-z_-]{35}`) },
    { label: 'Slack token', pattern: new RegExp(`${'xox'}[baprs]-[0-9A-Za-z-]{10,}`) },
  ];

  const files = committedTextFiles();
  assert.ok(files.length >= 10);
  for (const path of files) {
    const contents = readFileSync(path, 'utf8');
    for (const { label, pattern } of patterns) {
      assert.ok(!pattern.test(contents), `${path.slice(REPO.length)} contains a ${label}`);
    }
  }
});

test('no committed file leaks a local filesystem path or a private project name', () => {
  const needles = ['/home/' + 'syre', '/Users/' + 'syre', 'youngsyre' + '_wiki', 'Kou' + 'nisou'];
  for (const path of committedTextFiles()) {
    const contents = readFileSync(path, 'utf8');
    for (const needle of needles) {
      assert.ok(!contents.includes(needle), `${path.slice(REPO.length)} mentions ${needle}`);
    }
  }
});

test('the README documents every rule id', () => {
  const readme = readFileSync(join(REPO, 'README.md'), 'utf8');
  for (const id of RULE_IDS) {
    assert.ok(readme.includes(id), `README.md does not document ${id}`);
  }
});

test('the README documents every attack candidate id', () => {
  const { publicKey } = rsaPair();
  const pem = spkiPem(publicKey);
  const readme = readFileSync(join(REPO, 'README.md'), 'utf8');

  const seen = new Set<string>();
  for (const token of [
    makeToken({ alg: 'RS256' }, wellFormedClaims(), Buffer.alloc(256)),
    makeToken({ alg: 'ES256' }, wellFormedClaims(), Buffer.alloc(64, 1)),
    makeToken({ alg: 'HS256' }, wellFormedClaims(), Buffer.alloc(32)),
  ]) {
    const analysis = analyseToken(token, {
      now: new Date(1760000000 * 1000),
      keys: loadKeysFromText(pem, 'issuer-public.pem', Buffer.from(pem, 'utf8')),
    });
    for (const attack of analysis.attacks) seen.add(attack.id.split(':')[0] ?? attack.id);
  }

  assert.ok(seen.size >= 8, `expected a broad set of candidates, saw ${[...seen].join(', ')}`);
  for (const id of seen) {
    assert.ok(readme.includes(id), `README.md does not document ${id}`);
  }
});

test('the README documents every exit code the CLI can return', () => {
  const readme = readFileSync(join(REPO, 'README.md'), 'utf8');
  const cli = readFileSync(join(REPO, 'src', 'cli.ts'), 'utf8');
  for (const name of ['EXIT_OK', 'EXIT_FINDINGS', 'EXIT_USAGE', 'EXIT_UNPARSEABLE']) {
    assert.match(cli, new RegExp(`const ${name} = \\d`), `${name} should be a named constant`);
  }
  assert.match(readme, /## Exit codes/);
  for (const code of ['0', '1', '2', '3']) {
    assert.ok(readme.includes(`| \`${code}\` |`), `README.md does not document exit code ${code}`);
  }
});

test('the README states the real size of the built-in secret list', () => {
  const readme = readFileSync(join(REPO, 'README.md'), 'utf8');
  assert.ok(
    readme.includes(`${WEAK_SECRETS.length} hand-curated entries`),
    `README.md should say the list has ${WEAK_SECRETS.length} entries`,
  );
  assert.equal(new Set(WEAK_SECRETS).size, WEAK_SECRETS.length, 'the list should have no duplicates');
  assert.ok(WEAK_SECRETS.includes(''), 'the empty secret is the one that must never be missed');
});

test('the data file holding the secret list is plain, reviewable source', () => {
  const data = readFileSync(join(REPO, 'src', 'data', 'weak-secrets.ts'), 'utf8');
  assert.match(data, /Provenance/, 'the list should document where its entries come from');
  assert.ok(!data.includes('import '), 'the data file should be data, with no logic in it');
});
