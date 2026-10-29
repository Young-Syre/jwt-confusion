import type { Analysis, Finding, Severity } from './types.js';

export interface RenderOptions {
  readonly colour: boolean;
  /** Print generated tokens in full rather than abbreviated. */
  readonly fullTokens: boolean;
  readonly showAttacks: boolean;
}

/**
 * Generated tokens are abbreviated by default, and the shape of the
 * abbreviation is not arbitrary.
 *
 * A complete JWT is the exact shape that GitHub's push protection and most
 * secret scanners look for — two long base64url runs either side of a dot — so
 * a tool whose default output is whole tokens produces output that cannot
 * safely be pasted into an issue, a report draft or a commit message. Keeping
 * the head to 28 characters means no run of 30 or more base64url characters can
 * follow a dot within what is shown, whatever the header contains, and the
 * ellipsis breaks the run in any case. The 8-character tail is what makes
 * candidates distinguishable from one another: they share a header prefix but
 * never a signature.
 *
 * `--full-tokens` prints them whole, and `--json` always does, because that
 * output is meant for a machine.
 */
const TOKEN_HEAD = 28;
const TOKEN_TAIL = 8;

export function abbreviateToken(token: string): string {
  if (token.length <= TOKEN_HEAD + TOKEN_TAIL + 1) return token;
  return `${token.slice(0, TOKEN_HEAD)}…${token.slice(-TOKEN_TAIL)}`;
}

const SEVERITY_COLOUR: Readonly<Record<Severity, string>> = {
  critical: '\u001b[1;31m',
  high: '\u001b[31m',
  medium: '\u001b[33m',
  low: '\u001b[36m',
  info: '\u001b[90m',
};

const RESET = '\u001b[0m';
const BOLD = '\u001b[1m';
const DIM = '\u001b[90m';

function wrap(text: string, width: number, indent: string): string[] {
  const words = text.split(/\s+/).filter((word) => word.length > 0);
  const lines: string[] = [];
  let current = '';
  for (const word of words) {
    if (current.length === 0) {
      current = word;
    } else if (`${current} ${word}`.length + indent.length <= width) {
      current = `${current} ${word}`;
    } else {
      lines.push(indent + current);
      current = word;
    }
  }
  if (current.length > 0) lines.push(indent + current);
  return lines;
}

/** A `label  value` row whose continuation lines align under the value. */
function field(label: string, text: string, width: number): string[] {
  const head = `      ${label.padEnd(10)}`;
  const continuation = ' '.repeat(head.length);
  const wrapped = wrap(text, width, continuation);
  const first = wrapped[0];
  if (first === undefined) return [];
  return [head + first.slice(continuation.length), ...wrapped.slice(1)];
}

function severityCounts(findings: readonly Finding[]): string {
  const order: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const parts = order
    .map((severity) => ({ severity, count: findings.filter((f) => f.severity === severity).length }))
    .filter((entry) => entry.count > 0)
    .map((entry) => `${entry.count} ${entry.severity}`);
  return parts.length === 0 ? 'none' : parts.join(', ');
}

export function renderText(analysis: Analysis, options: RenderOptions): string {
  const paint = (text: string, colour: string): string => (options.colour ? `${colour}${text}${RESET}` : text);
  const lines: string[] = [];
  const width = 92;

  const { structure } = analysis;
  const algorithm = structure.algorithm;

  lines.push(paint(`${analysis.tool} ${analysis.version}`, BOLD));
  lines.push('');

  lines.push(paint('TOKEN', BOLD));
  const algorithmDetail = [
    algorithm.family,
    algorithm.hash ?? 'no digest',
    algorithm.registered ? 'registered' : 'NOT a registered algorithm name',
  ];
  if (algorithm.caseVariantOf !== null) {
    algorithmDetail.push(`case variant of ${algorithm.caseVariantOf}`);
  }
  lines.push(`  segments            ${structure.segmentCount}`);
  lines.push(`  algorithm           ${algorithm.declared || '(absent)'} (${algorithmDetail.join(', ')})`);
  const expected =
    algorithm.signatureBytes === null ? 'key-size dependent' : `expected ${algorithm.signatureBytes}`;
  lines.push(`  signature           ${structure.signatureBytes} bytes (${expected})`);
  lines.push(
    `  key locators        ${structure.keyLocatorHeaders.length === 0 ? 'none' : structure.keyLocatorHeaders.join(', ')}`,
  );
  lines.push(
    `  payload             ${structure.payloadIsJsonObject ? `JSON object, ${Object.keys(structure.payload ?? {}).length} claims` : 'not a JSON object'}`,
  );
  if (structure.lifetimeSeconds !== null) {
    lines.push(`  lifetime            ${structure.lifetimeSeconds}s (exp - iat)`);
  }
  if (structure.expired !== null) {
    lines.push(`  expired             ${structure.expired ? 'yes' : 'no'} (as at ${analysis.analysedAt})`);
  }
  lines.push('');

  lines.push(paint('HEADER', BOLD));
  for (const line of JSON.stringify(structure.header, null, 2).split('\n')) {
    lines.push(`  ${line}`);
  }
  lines.push('');

  lines.push(paint('REGISTERED CLAIMS', BOLD));
  for (const claim of structure.claims) {
    const value = claim.present ? claim.rendered ?? '' : paint('absent', DIM);
    lines.push(`  ${claim.claim.padEnd(5)} ${value}`);
  }
  lines.push('');

  if (structure.encodingIssues.length > 0) {
    lines.push(paint('ENCODING', BOLD));
    for (const issue of structure.encodingIssues) {
      lines.push(`  ${issue.segment.padEnd(10)} ${issue.issue}`);
      lines.push(...wrap(issue.detail, width, '             '));
    }
    lines.push('');
  }

  lines.push(paint('SIGNATURE', BOLD));
  if (structure.signatureVerification.length === 0) {
    lines.push('  no key or secret was available to check the signature against');
  } else {
    for (const result of structure.signatureVerification) {
      const verdict = result.valid ? paint('VALID  ', SEVERITY_COLOUR.critical) : 'invalid';
      lines.push(`  ${verdict} ${result.source}`);
      lines.push(...wrap(result.detail, width, '             '));
    }
  }
  lines.push('');

  lines.push(paint(`FINDINGS (${severityCounts(analysis.findings)})`, BOLD));
  if (analysis.findings.length === 0) {
    lines.push('  none');
  }
  for (const finding of analysis.findings) {
    const tag = paint(`[${finding.severity}]`, SEVERITY_COLOUR[finding.severity]);
    const status = finding.confirmed ? paint('confirmed locally', BOLD) : paint('needs a request to confirm', DIM);
    lines.push(`  ${tag} ${finding.id}  ${finding.name}  ${status}`);
    lines.push(...wrap(finding.rationale, width, '      '));
    for (const [key, value] of Object.entries(finding.evidence)) {
      if (value === null || value === undefined) continue;
      const rendered = Array.isArray(value) ? value.join(', ') : String(value);
      if (rendered.length === 0) continue;
      const wrapped = wrap(`\u00b7 ${key}: ${rendered}`, width, '        ');
      const firstLine = wrapped[0];
      if (firstLine !== undefined) lines.push(`      ${firstLine.trimStart()}`, ...wrapped.slice(1));
    }
    lines.push('');
  }

  if (options.showAttacks) {
    lines.push(paint(`ATTACK MATRIX (${analysis.attacks.length} candidates)`, BOLD));
    if (analysis.attacks.length === 0) {
      lines.push('  none applicable');
    }
    for (const attack of analysis.attacks) {
      lines.push(`  ${paint(attack.id, BOLD)}  ${attack.name}`);
      lines.push(...wrap(attack.rationale, width, '      '));
      lines.push(
        `      ${'token'.padEnd(10)}${options.fullTokens ? attack.token : abbreviateToken(attack.token)}`,
      );
      if (!options.fullTokens) {
        lines.push(
          `      ${' '.repeat(10)}${paint('abbreviated — --full-tokens or --json prints it whole', DIM)}`,
        );
      }
      lines.push(...field('signed', attack.signing, width));
      lines.push(...field('checked', attack.verified ?? 'nothing beyond its structure', width));
      for (const prerequisite of attack.prerequisites) {
        lines.push(...field('needs', prerequisite, width));
      }
      for (const artifact of attack.artifacts) {
        lines.push(...field('artifact', `${artifact.name} — ${artifact.description}`, width));
        for (const line of artifact.content.trimEnd().split('\n')) {
          lines.push(`                ${line}`);
        }
      }
      lines.push('');
    }
  }

  if (analysis.notes.length > 0) {
    lines.push(paint('NOTES', BOLD));
    for (const note of analysis.notes) {
      lines.push(...wrap(`- ${note}`, width, '  '));
    }
    lines.push('');
  }

  lines.push(
    paint(
      'No network request was made. jku, x5u and URL-shaped kid values are reported, never fetched.',
      DIM,
    ),
  );

  return `${lines.join('\n')}\n`;
}

export function renderJson(analysis: Analysis, options: { showAttacks: boolean }): string {
  const payload = options.showAttacks ? analysis : { ...analysis, attacks: [] };
  return `${JSON.stringify(payload, null, 2)}\n`;
}
