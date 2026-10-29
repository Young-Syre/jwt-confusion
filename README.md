# jwt-confusion

[![tests](https://github.com/Young-Syre/jwt-confusion/actions/workflows/tests.yml/badge.svg)](https://github.com/Young-Syre/jwt-confusion/actions/workflows/tests.yml)
[![Node](https://img.shields.io/badge/node-20%20%7C%2022%20%7C%2024-brightgreen.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6.svg)](./tsconfig.json)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![dependencies: none](https://img.shields.io/badge/dependencies-none-lightgrey.svg)](#dependencies)

Read a JWT and report what it reveals about the code that will verify it, then
generate the candidate tokens that settle each question. Offline, always: `jku`
and `x5u` URLs are reported and never requested.

---

## A JWT tells the verifier how to verify it

A JWT is the only common credential format that tells the code checking it how
to check it.

The signature covers the header, and the header contains `alg`. A verifier is
therefore handed, in a single blob, both the assertion it is meant to doubt and
the instructions for resolving that doubt. The specification is explicit that
the instructions are untrusted — RFC 8725 spends most of its length saying so —
but the shape of the data pushes every implementer the same way, because the
convenient implementation and the correct one differ by exactly one decision:
whether the algorithm comes from the token or from your own configuration.

Take the API shape that JWT libraries offered for years:

```js
jwt.verify(token, key);
```

There is no algorithm in that call. The library must get one from somewhere, and
the only place it has is the token. So `alg: none` means there is nothing to
check. `alg: HS256` on a service holding an RSA key means the public key gets
run through HMAC — and the public key is public, so the attacker can compute
that MAC too. One parameter decides it:

```js
jwt.verify(token, key, { algorithms: ['RS256'] });
```

The same pattern repeats a level up, in key *selection*. A verifier with more
than one key has to pick one, and the header offers four ways to help:

| Header | What it asks the verifier to do |
| --- | --- |
| `kid` | look a key up by a name the attacker chose |
| `jku` | fetch a key set from a URL the attacker chose |
| `x5u` | fetch a certificate chain from a URL the attacker chose |
| `jwk` | use the key enclosed with the token |

Each is legal. Each is a lookup whose input is attacker-controlled. `kid` ends
up in a file path or a SQL query often enough that both have their own rule
below; `jku` and `x5u` turn the verifier into an HTTP client aimed wherever the
token points, in a code path that by definition runs before authentication; and
`jwk` is the reductio — a token that supplies the key it wants to be checked
against, which is no check at all.

None of this is exotic. It is the ordinary consequence of putting the
verification parameters inside the thing being verified, and it is why the same
few findings keep appearing in different services a decade after they were
first written up.

### What this tool does about it

A token is evidence about the verifier that issued it. `jwt-confusion` reads
that evidence, says what each piece implies, and — the part that matters —
separates two kinds of claim:

- **Confirmed.** Established here, with cryptography, on your machine. The MAC
  matched. The signature verified under the embedded key. The secret was
  recovered. These need no further argument.
- **Needs a request to confirm.** An observation about the token's shape that
  implies something about the verifier. `jku` is present, so the verifier
  *probably* fetches it — but nothing offline can tell you whether it does.

Findings of the second kind are where reports get written badly. So for each
one, the tool builds the token that would settle it: correctly structured,
correctly signed, and checked locally before it is printed.

---

## Install

```sh
git clone https://github.com/Young-Syre/jwt-confusion
cd jwt-confusion
npm install
npm run build
npm link        # optional, puts `jwt-confusion` on your PATH
```

Node 20 or newer. No runtime dependencies; TypeScript and `@types/node` are the
only devDependencies. Without `npm link`, invoke it as `node dist/src/cli.js`.

---

## Usage

Everything below was produced by running the commands shown. There are no token
or key fixtures in this repository — the `sample` subcommand mints what the
examples need, which is also where the test suite gets its material. See
[Why there are no key fixtures here](#why-there-are-no-key-fixtures-here).

### A token on its own

```sh
jwt-confusion sample > weak.jwt
jwt-confusion "$(cat weak.jwt)" --now 1760100000 --no-attacks
```

```
jwt-confusion 0.1.0

TOKEN
  segments            3
  algorithm           HS256 (hmac, sha256, registered)
  signature           32 bytes (expected 32)
  key locators        kid
  payload             JSON object, 4 claims

HEADER
  {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "../../config/keys/signing.pem"
  }

REGISTERED CLAIMS
  iss   absent
  sub   "user-1042"
  aud   absent
  exp   absent
  nbf   absent
  iat   1760000000 (2025-10-09T08:53:20.000Z)
  jti   absent

SIGNATURE
  VALID   built-in list of common defaults
             HS256 with the secret "secret"

FINDINGS (1 critical, 2 high, 1 medium, 1 low)
  [critical] JWT-WEAK-HMAC-SECRET  HMAC secret recovered from a list of common defaults  confirmed locally
      The signing secret was recovered locally, so the signature on this token can be
      reproduced and any claim in it can be rewritten. An HMAC secret is a password with
      none of the protections passwords get: no rate limit, no lockout, and an offline
      oracle in every token the service hands out.
      · secret: secret
      · origin: built-in list of common defaults
      · candidatesTried: 52

  [high] JWT-KID-TRAVERSAL  path traversal in kid  needs a request to confirm
      The key identifier contains path traversal. Where `kid` is used to build a filename,
      the attacker chooses which file becomes the verification key. The useful target is not
      a key at all: a file whose contents are empty or predictable lets the attacker compute
      the HMAC themselves, which is why `/dev/null` appears in the attack matrix.
      · kid: ../../config/keys/signing.pem

  [high] JWT-NO-EXP  no expiry claim  needs a request to confirm
      The token carries no `exp`. Unless the verifier requires one, this token is valid
      until the signing key is rotated, which in practice means indefinitely. Any copy that
      leaks — from a log, a proxy cache, a browser history, a support ticket — remains a
      working credential.
      · claimsPresent: sub, name, role, iat

  [medium] JWT-NO-AUD  no audience claim  needs a request to confirm
      Without `aud`, nothing in the token says which service it was minted for. Every
      service that trusts this issuer will accept it, so a token issued for a low-value API
      is replayable against a high-value one. This is the claim that makes a token
      confused-deputy-resistant, and it is the one most often left out.
      · claimsPresent: sub, name, role, iat

  [low] JWT-NO-ISS  no issuer claim  needs a request to confirm
      Without `iss`, a verifier that trusts more than one issuer cannot tell them apart, and
      key selection has to fall back on something less trustworthy — usually `kid`, which
      the attacker also controls.
      · claimsPresent: sub, name, role, iat

No network request was made. jku, x5u and URL-shaped kid values are reported, never fetched.
```

`--now` pins the clock so the output is reproducible; leave it off in real use.

### With the issuer's public key

The interesting check needs the key. `sample --kind confused` mints the token a
successful algorithm-confusion attack produces — HS256, keyed with the exact
bytes of the public key file — so the detection can be reproduced end to end:

```sh
jwt-confusion sample --kind confused --write-key issuer-public.pem > confused.jwt
jwt-confusion "$(cat confused.jwt)" \
  --public-key issuer-public.pem --expect-alg RS256 --now 1760100000 --no-attacks
```

The signature and findings sections of that output, with the claim-hygiene
findings trimmed:

```
SIGNATURE
  VALID   issuer-public.pem (as an HMAC secret, file-bytes)
             HS256 over the signing input with the key file read verbatim, including any
             trailing newline

FINDINGS (1 critical, 2 high, 1 medium, 1 low)
  [critical] JWT-ALG-CONFUSION-HS  asymmetric public key used as an HMAC secret  confirmed locally
      The signature on this token is a valid HMAC computed over the signing input with the
      supplied public key as the secret. This is algorithm confusion, and it is no longer a
      hypothesis: the MAC was recomputed locally and matched. Whatever produced or accepted
      this token selected its verification function from the `alg` header while holding a
      single key, so a public value became a signing key.
      · keySource: issuer-public.pem
      · matchedRepresentation: file-bytes
      · representationDescription: the key file read verbatim, including any trailing
        newline
      · hmacAlgorithm: HS256
```

`matchedRepresentation: file-bytes` is the part that matters. The attack is not
"use the public key", it is "use the exact bytes the target's code passes to its
HMAC function", and a PEM re-exported by a crypto library is not byte-identical
to the PEM on disk. Between five and nine representations are derived from a
supplied key, depending on its type and how the file is formatted, and each is
tried; the one that matched is named.

### The attack matrix

Drop `--no-attacks` and every applicable candidate is generated, signed and
checked:

```sh
jwt-confusion sample --kind rsa --write-key rsa-public.pem > rsa.jwt
jwt-confusion "$(cat rsa.jwt)" --public-key rsa-public.pem \
  --now 1760100000 --attacker-host collab.example --max-confusion-variants 2
```

Three of the nine candidates that run produces:

```
ATTACK MATRIX (9 candidates)
  ATK-ALG-NONE  unsecured token, canonical spelling
      Asks the verifier to accept an assertion with no signature at all. The first thing to
      try, and still the thing that works when a verifier takes its algorithm from the
      token.
      token     eyJhbGciOiJub25lIiwidHlwIjoi…wMDAwfQ.
                abbreviated — --full-tokens or --json prints it whole
      signed    not signed; the signature segment is empty, with the trailing dot retained
      checked   structure only — there is nothing to verify on an unsecured JWS

  … six candidates omitted …

  ATK-HS-WITH-PUBKEY:file-bytes  HS256 signed with the public key (file-bytes)
      Algorithm confusion. The verifier holds one key and chooses its verification function
      from the header, so naming an HMAC algorithm makes it use the public key as a shared
      secret — and the public key is public. Which byte representation works depends on how
      the target loads its key, so there is one candidate per representation: 7 were derived
      from this key and 2 are shown. This one is keyed with the key file read verbatim,
      including any trailing newline.
      token     eyJhbGciOiJIUzI1NiIsInR5cCI6…uB1t9PYA
                abbreviated — --full-tokens or --json prints it whole
      signed    HMAC-SHA256 over the signing input, keyed with the key file read verbatim,
                including any trailing newline
      checked   recomputed the MAC after assembly and confirmed it matches the signature
                segment
      needs     The target must verify with the same key you supplied (rsa-public.pem).
      needs     The target must pass that key to its HMAC function in this exact byte
                representation.

  ATK-HS-WITH-PUBKEY:file-bytes-trimmed  HS256 signed with the public key (file-bytes-trimmed)
      The same attack keyed with a different byte representation: the key file with trailing
      whitespace stripped.
      token     eyJhbGciOiJIUzI1NiIsInR5cCI6…uTVUB_is
                abbreviated — --full-tokens or --json prints it whole
      signed    HMAC-SHA256 over the signing input, keyed with the key file with trailing
                whitespace stripped
      checked   recomputed the MAC after assembly and confirmed it matches the signature
                segment
      needs     The target must verify with the same key you supplied (rsa-public.pem).
      needs     The target must pass that key to its HMAC function in this exact byte
                representation.

```

Tokens are abbreviated in text output on purpose: a whole JWT is the exact shape
secret scanners match, so the default output is safe to paste into an issue or a
report. `--full-tokens` prints them whole, and `--json` always does.

### Rewriting claims

```sh
jwt-confusion "$(cat weak.jwt)" --claim role=admin --claim 'scope=["read","write"]' --json
```

Every generated candidate carries the rewritten claims. Values are parsed as
JSON when they parse and used as strings otherwise. With no `--claim`, the
payload segment of each candidate is the **original bytes**, not a re-encoding —
so a candidate that fails failed because of the attack, not because the payload
looked different.

### In a pipeline

```sh
jwt-confusion "$TOKEN" --expect-alg RS256 --fail-on high --json > findings.json
```

### Full option list

```
jwt-confusion 0.1.0 — offline JWT verifier-weakness analyser and attack-matrix generator

USAGE
  jwt-confusion [analyse] <token|-> [options]
  jwt-confusion sample [--kind <kind>] [--write-key <path>]

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
                            present. One of info, low, medium, high, critical, or
                            "never" (default: high).
  --no-color, --no-colour   Disable colour. Colour is off automatically when
                            output is not a terminal, or when NO_COLOR is set.
  -h, --help                This text.
  -V, --version             Version only.

SAMPLE OPTIONS
  --kind <kind>             One of weak-hmac, unsecured, rsa, confused,
                            embedded-jwk, ecdsa-zero (default: weak-hmac).
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
```

---

## Rules

Severity describes the verifier weakness, not the token: a token with no `exp`
is not itself dangerous, but a verifier that will accept it forever is.
**Confirmed** marks the findings established locally with cryptography;
everything else is an inference that needs a request to the target before it
belongs in a report.

| ID | Severity | Confirmed | What it means |
| --- | --- | --- | --- |
| `JWT-ALG-NONE` | critical | no | `alg: none`. Integrity rests entirely on the verifier refusing to honour the header. |
| `JWT-ALG-NONE-VARIANT` | high | no | `alg` differs from `none` only by case, which defeats a blocklist that compares case-insensitively elsewhere. |
| `JWT-SIG-EMPTY` | high | no | A signing algorithm is named but no signature bytes are present. Some verifiers short-circuit. |
| `JWT-ALG-UNKNOWN` | medium | no | `alg` is not an exact match for a registered JWS algorithm, including the case where it differs from one only by case. How the verifier reacts is the question. |
| `JWT-ALG-MISMATCH` | high | no | The header algorithm differs from the one you declared with `--expect-alg`. |
| `JWT-ALG-CONFUSION-HS` | critical | **yes** | The signature is a valid HMAC keyed with the supplied public key. Algorithm confusion, recomputed and matched locally. |
| `JWT-ALG-CONFUSION-CANDIDATE` | info | no | An asymmetric token plus a supplied key: the prerequisites for a confusion attempt are met, and candidates were generated. |
| `JWT-WEAK-HMAC-SECRET` | critical | **yes** | The signing secret was recovered from the candidate list. Any claim can be rewritten. |
| `JWT-EMBEDDED-JWK` | critical | no | The header carries the key it wants to be verified against. |
| `JWT-JWK-SELF-SIGNED` | critical | **yes** | The signature verifies under that embedded key: the token is entirely self-asserted. |
| `JWT-JKU-PRESENT` | high | no | A key-set URL in the header. SSRF into the verifier's key fetch, then trust in what comes back. Reported, never fetched. |
| `JWT-X5U-PRESENT` | high | no | The same, for an X.509 certificate chain. Reported, never fetched. |
| `JWT-KID-TRAVERSAL` | high | no | Path traversal in `kid`. The attacker picks the key file. |
| `JWT-KID-PATH` | medium | no | `kid` is path-shaped, implying a filesystem lookup worth probing. |
| `JWT-KID-URL` | high | no | `kid` holds a URL, implying the verifier dereferences it. Reported, never fetched. |
| `JWT-KID-SQLMETA` | high | no | SQL metacharacters in `kid`. A `UNION SELECT` makes the attacker the author of the verification key. |
| `JWT-SIG-LENGTH` | high | no | The signature is not the length the declared algorithm produces. Truncation is the interesting case. |
| `JWT-RSA-SMALL-KEY` | medium | with a key | The RSA modulus is at most 1024 bits, below the RFC 7518 §3.3 minimum. Inferred from the signature length, or measured exactly when a supplied key verifies the token. |
| `JWT-ECDSA-ZERO-SIG` | critical | **yes** | Both halves of the ECDSA signature are zero, which an affected Java runtime accepts for any message (CVE-2022-21449). |
| `JWT-B64-NONCANONICAL` | medium | no | A segment is not canonical base64url, so only a lenient decoder accepts it, so two encodings of the same bytes both reach the application. |
| `JWT-CRIT-UNKNOWN` | medium | no | `crit` is malformed, names an unrecognised extension, or names a header parameter that is absent. The verifier is obliged to reject it. |
| `JWT-NO-EXP` | high | no | No `exp`. Unless the verifier demands one, the token is valid until the key is rotated. |
| `JWT-LONG-EXP` | medium | no | The validity window exceeds `--max-lifetime-days` (30 by default). |
| `JWT-EXPIRED` | info | no | Already expired against the analysis clock. Context for how to read the rest of the output. |
| `JWT-NO-AUD` | medium | no | No `aud`, so the token is replayable against every service that trusts the issuer. |
| `JWT-NO-ISS` | low | no | No `iss`, so a multi-issuer verifier must fall back on something the attacker also controls. |

## The attack matrix

Each candidate is a complete compact JWS, checked locally before it is printed.
What "checked" means is stated per candidate: a MAC recomputed, a signature
verified under a named key, or — for the unsigned ones — nothing beyond their
structure, which is said rather than left to assumption.

| ID | What it tests | How it is signed |
| --- | --- | --- |
| `ATK-ALG-NONE` | a verifier that takes its algorithm from the token | not signed; empty signature segment |
| `ATK-ALG-NONE-VARIANT` | a case-insensitive `none` blocklist | not signed |
| `ATK-SIG-STRIPPED` | a verifier that short-circuits before the comparison | not signed; original header preserved |
| `ATK-HS-WITH-PUBKEY` | HS/RS algorithm confusion, one candidate per byte representation of the supplied key | HMAC-SHA256 keyed with that representation |
| `ATK-HS-RECOVERED-SECRET` | that claims can be rewritten once the secret is known | HMAC with the recovered secret |
| `ATK-EMBEDDED-JWK` | a verifier that resolves keys from the `jwk` header | RS256 with a keypair generated for this run |
| `ATK-JKU-REMOTE` | a verifier that fetches and trusts a remote key set; ships the JWKS to serve | RS256 with a keypair generated for this run |
| `ATK-KID-DEVNULL` | `kid` resolved to a file path, traversed to an empty file | HMAC-SHA256 with a zero-length key |
| `ATK-KID-SQLI` | `kid` interpolated into a key lookup query | HMAC-SHA256 with the injected literal |
| `ATK-ECDSA-ZERO-SIG` | CVE-2022-21449 on an affected Java runtime | not signed; `r` and `s` set to zero |

---

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Analysed. Nothing at or above the `--fail-on` threshold (default `high`). |
| `1` | Analysed. At least one finding at or above the threshold. |
| `2` | Usage error: an unknown flag, a missing value, an unreadable key file. |
| `3` | The input is not a parseable compact JWS. |

`--fail-on never` always exits 0 on a token that parses.

---

## What this tool does not do

- **It makes no network request, ever.** It does not fetch `jku`, `x5u` or a
  URL-shaped `kid`; it reports them. Nothing in `src/` imports `node:http`,
  `node:https`, `node:net`, `node:tls`, `node:dns` or `node:child_process`, and
  nothing calls `fetch`. A test asserts this against the source tree, so the
  claim fails the build if it ever stops being true.
- **It does not tell you the target is vulnerable.** It tells you what the token
  implies and hands you the token that would settle it. Only a response from the
  target closes that gap, which is what the confirmed/unconfirmed split on every
  finding is for.
- **It is not a cracker.** The built-in secret list is 52 hand-curated entries —
  documentation placeholders, framework defaults, breach-list staples — and
  exists so that the catastrophic case is never missed for want of trying. An
  empty result is not evidence of a strong secret. Use hashcat mode 16500 or
  John with a real wordlist.
- **It does not handle JWEs.** Encrypted tokens have five segments; they are
  detected and rejected with that explanation rather than mangled.
- **It does not implement any cryptography.** Every primitive comes from
  `node:crypto`. The code here is concerned with feeding Node the right
  parameters, which for JOSE is the part that is easy to get wrong: a JWS ECDSA
  signature is raw `r || s` and needs `dsaEncoding: 'ieee-p1363'`, RSA-PSS needs
  its salt length pinned to the digest length, and EdDSA takes a null algorithm.
- **It does not check `nbf`.** `nbf` is reported in the claim table but has no
  rule of its own, because a not-yet-valid token says more about clock skew than
  about the verifier.

### Known limitations

- The HS/RS confusion check needs the public key. Without one it can only say
  the token is a *candidate* for the attack, which is what
  `JWT-ALG-CONFUSION-CANDIDATE` means. There is no attempt to recover a modulus
  from two signatures by the same key — that is a real technique, and this tool
  does not implement it.
- RSA signature-length checking is heuristic. An RSA signature is as long as the
  modulus, which the token does not carry, so only implausible lengths can be
  flagged. Supply the key and the check becomes exact.
- `JWT-KID-PATH` and `JWT-KID-SQLMETA` are pattern matches on the `kid` value. A
  `kid` that is a bare UUID in a service which nonetheless interpolates it into
  SQL will not be flagged; the absence of a finding here is not evidence of a
  safe lookup.
- Traversal depth in `ATK-KID-DEVNULL` is a guess. Six levels is a common fit,
  and the candidate says so rather than pretending otherwise.
- The `crit` rule treats `b64` (RFC 7797) as the only known extension, so a
  deployment with its own registered extension will see a false positive.
- Claim overrides are only applied when the payload is a JSON object. For a
  nested JWT or a binary payload they are declined, and the candidate says so.
- `--secret-list` is read into memory and tried entry by entry. It is meant for
  a handful of project-specific guesses, not for a wordlist.

---

## Why there are no key fixtures here

A PEM-wrapped private key and a complete JWT are both literals that GitHub's
push protection blocks, and it is right to. So this repository contains neither,
and the test suite builds what it needs at run time:

- Ed25519 keys are derived deterministically from a committed hex seed. An
  Ed25519 PKCS#8 document is a fixed 16-byte prefix followed by the 32-byte
  seed, so the same seed reproduces the same keypair on every machine with no
  PEM anywhere.
- RSA and EC keys cannot be seeded through `node:crypto`, and deriving them from
  a seed would mean implementing prime generation — exactly the hand-rolled
  cryptography this project refuses to do. They are generated once per test
  process instead. Nothing in the suite depends on a *particular* RSA key, only
  on having one.
- Every token in the tests, and every token in this README, was minted at run
  time by `jwt-confusion sample`.

A test walks the repository and fails if any committed file matches a PEM
private key, a complete JWT, or half a dozen other credential shapes.

## Dependencies

None at runtime. `typescript` and `@types/node` are the only devDependencies,
and a test asserts that this stays true.

## Tests

```sh
npm test        # builds, then runs node --test over dist/test/*.test.js
```

119 test cases and 352 assertions, covering every rule both positively and
negatively; base64url canonicality at every residue length; the generated
candidates, each verified with the key or secret it claims; the CLI's exit codes
and both output modes; and the repository hygiene checks described above.

## Licence

MIT. See [LICENSE](./LICENSE).
