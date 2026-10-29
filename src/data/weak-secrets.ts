/**
 * Candidate HMAC secrets, hand-curated.
 *
 * Provenance, so you can judge the list rather than trust it. Every entry
 * belongs to one of four groups:
 *
 *  1. Placeholders that ship in documentation and get deployed unchanged.
 *     `your-256-bit-secret` is the example on jwt.io's own debugger page;
 *     `your_jwt_secret` and `jwtPrivateKey` are the placeholders in widely
 *     copied tutorial code.
 *  2. Framework and boilerplate defaults of the `changeme` family, which exist
 *     specifically so the application starts before anyone configures it.
 *  3. The handful of passwords that top every published breach-corpus
 *     frequency list.
 *  4. Words a developer reaches for when writing a value they intend to
 *     replace later: `secret`, `test`, `dev`, `local`.
 *
 * The empty string is first and matters most. Several libraries will happily
 * compute an HMAC with a zero-length key when the configured secret is
 * undefined, which turns a missing environment variable into a signing oracle
 * for anyone who guesses that it is missing.
 *
 * This list is forty-odd entries and is not a cracking tool. It exists so that
 * the catastrophic case is never missed for want of trying. If it comes back
 * empty, that is not evidence of a strong secret — point hashcat (mode 16500)
 * or john at the token with a real wordlist. The README says the same thing.
 */
export const WEAK_SECRETS: readonly string[] = Object.freeze([
  '',
  'secret',
  'Secret',
  'SECRET',
  'secret1',
  'secretkey',
  'secret-key',
  'secret_key',
  'mysecret',
  'mysecretkey',
  'supersecret',
  'super-secret',
  'topsecret',
  'shhhhh',
  'changeme',
  'change-me',
  'change_me',
  'CHANGEME',
  'default',
  'password',
  'password1',
  'Password1',
  'passw0rd',
  '123456',
  '12345678',
  'qwerty',
  'letmein',
  'admin',
  'administrator',
  'root',
  'test',
  'testing',
  'dev',
  'development',
  'staging',
  'production',
  'local',
  'localhost',
  'example',
  'jwt',
  'jwtsecret',
  'jwt-secret',
  'jwt_secret',
  'JWT_SECRET',
  'your_jwt_secret',
  'your-256-bit-secret',
  'jwtPrivateKey',
  'token',
  'key',
  'signature',
  'hello',
  'hunter2',
]);
