import crypto from 'crypto';

/**
 * Macaroon-based API tokens with decentralized caveat attenuation (#930).
 *
 * A macaroon is an *append-only* authorization token: the issuer signs an
 * identifier with a root key, and anyone holding the token can add caveats
 * (restrictions) without contacting the server:
 *
 *   sig0 = HMAC(rootKey, identifier)
 *   sigN = HMAC(sigN-1, caveatN)
 *
 * Because HMAC chaining is one-way, an attenuated token can only ever be *more*
 * restricted than its parent — a delegate cannot remove the wallet, scope or
 * expiry caveats, and cannot mint a token at all without the root key.
 * Verification recomputes the chain, so no database lookup is required.
 *
 * Token format (`.`-separated; base64url has no `.`):
 *
 *   `MCR1.<base64url(identifier)>.[<base64url(caveat)>…].<base64url(signature)>`
 *
 * Supported first-party caveats:
 *
 *   - `wallet = G...` / `wallet_id = G...`
 *   - `action = read` / `scope = wallets:read` (context must grant it)
 *   - `method = GET`
 *   - `path = /api/v1/wallets` or `/api/v1/wallets/*` (prefix)
 *   - `user = <id>`
 *   - `expires = 2026-12-31T00:00:00Z` / `expires_ms = 1798675200000`
 *   - `not_before = <ISO date>` / `not_before_ms = <unix ms>`
 *
 * Third-party caveats (`third_party = <provider>|<base64url(identifier)>`)
 * require a matching discharge macaroon to be presented alongside the root
 * token; both signatures are verified locally.
 *
 * Unknown caveats fail closed: a verifier that does not understand a
 * restriction must never silently ignore it.
 */

export const MACAROON_VERSION = 'MCR1';
export const MACAROON_IDENTIFIER_VERSION = 1;

const TOKEN_PREFIX = `${MACAROON_VERSION}.`;
const SIGNATURE_BYTES = 32;
const MAX_CAVEAT_LENGTH = 4096;
const MAX_DISCHARGE_DEPTH = 3;

export interface MacaroonIdentifier {
  version: typeof MACAROON_IDENTIFIER_VERSION;
  /** Root key id used to sign this token. */
  kid: string;
  /** Owning user (mapped onto `request.user.id`). */
  userId: string;
  /** Optional email so the token can satisfy the existing UserPayload shape. */
  email?: string;
  /** Mint time in Unix milliseconds. */
  issuedAt: number;
  /** Random nonce; keeps two identical mints distinct. */
  nonce: string;
  label?: string;
}

export type MacaroonRootKey = string | Buffer;

export interface MacaroonMintInput {
  userId: string;
  email?: string;
  /** Root key id; defaults to the service's primary key id. */
  kid?: string;
  label?: string;
  caveats?: Array<string | MacaroonThirdPartyCaveat>;
  issuedAt?: number;
  nonce?: string;
}

export interface MacaroonThirdPartyCaveat {
  type: 'third_party';
  /** Caveat issuer identifier (e.g. `billing-service`). */
  provider: string;
  /** Identifier of the discharge macaroon expected from that provider. */
  identifier: string;
}

export interface MacaroonVerificationContext {
  method?: string;
  path?: string;
  walletId?: string;
  userId?: string;
  action?: string;
  scopes?: readonly string[];
}

export interface MacaroonVerifyOptions {
  now?: Date | number;
  /** Discharge macaroons presented for third-party caveats. */
  discharges?: readonly string[];
  /** Maximum recursive discharge verification depth. */
  maxDepth?: number;
}

export type MacaroonInvalidReason =
  | 'malformed_token'
  | 'unsupported_version'
  | 'unknown_root_key'
  | 'invalid_signature'
  | 'unknown_caveat'
  | 'caveat_failed'
  | 'missing_discharge'
  | 'invalid_discharge'
  | 'discharge_too_deep';

export interface MacaroonVerificationResult {
  valid: boolean;
  reason?: MacaroonInvalidReason;
  /** Human-readable explanation for logs; never returned to clients verbatim. */
  detail?: string;
  identifier?: MacaroonIdentifier;
  caveats: string[];
  /** Recomputed signature (hex) — useful for tests/audit correlation. */
  signature?: string;
}

export interface MacaroonParseResult {
  identifierRaw: string;
  identifier: MacaroonIdentifier;
  caveats: string[];
  signature: string;
}

export class MacaroonConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MacaroonConfigurationError';
  }
}

function toBase64Url(value: Buffer | string): string {
  return Buffer.from(value).toString('base64url');
}

function fromBase64Url(value: string): Buffer | null {
  try {
    const decoded = Buffer.from(value, 'base64url');
    // Reject lenient decodes (e.g. `%%%` also produces an empty buffer).
    if (decoded.toString('base64url') !== value) return null;
    return decoded;
  } catch {
    return null;
  }
}

function hmac(key: crypto.BinaryLike, data: string): Buffer {
  return crypto.createHmac('sha256', key).update(data, 'utf8').digest();
}

function deriveRootKey(key: MacaroonRootKey): Buffer {
  if (Buffer.isBuffer(key)) {
    if (key.length < 16) {
      throw new MacaroonConfigurationError('Macaroon root keys must be at least 16 bytes');
    }
    return key;
  }
  if (typeof key !== 'string' || key.length < 16) {
    throw new MacaroonConfigurationError('Macaroon root keys must be at least 16 characters');
  }
  // Hash string secrets so arbitrary-length configuration is accepted while
  // every HMAC still uses a fixed 256-bit key.
  return crypto.createHash('sha256').update(key, 'utf8').digest();
}

function constantTimeEqual(left: Buffer, right: Buffer): boolean {
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function serializeIdentifier(identifier: MacaroonIdentifier): string {
  return JSON.stringify(identifier);
}

function normalizeIssuedAt(value: Date | number | undefined): number {
  if (value === undefined) return Date.now();
  const timestamp = value instanceof Date ? value.getTime() : value;
  if (!Number.isFinite(timestamp)) {
    throw new MacaroonConfigurationError('issuedAt must be a valid date');
  }
  return timestamp;
}

/** Formats a first-party `key = value` caveat. */
export function firstPartyCaveat(key: string, value: string | number): string {
  const normalizedKey = key.trim();
  if (!normalizedKey || /[=,\r\n]/.test(normalizedKey)) {
    throw new MacaroonConfigurationError('Invalid caveat key');
  }
  const normalizedValue = String(value).trim();
  if (!normalizedValue || /[\r\n]/.test(normalizedValue)) {
    throw new MacaroonConfigurationError('Invalid caveat value');
  }
  const caveat = `${normalizedKey} = ${normalizedValue}`;
  if (caveat.length > MAX_CAVEAT_LENGTH) {
    throw new MacaroonConfigurationError('Caveat exceeds maximum length');
  }
  return caveat;
}

/** Formats a third-party caveat that requires a matching discharge macaroon. */
export function thirdPartyCaveat(caveat: MacaroonThirdPartyCaveat): string {
  const provider = caveat.provider.trim();
  if (!provider || provider.includes('|')) {
    throw new MacaroonConfigurationError('Third-party provider must not be empty or contain "|"');
  }
  if (!caveat.identifier) {
    throw new MacaroonConfigurationError('Third-party caveat requires a discharge identifier');
  }
  return firstPartyCaveat(
    'third_party',
    `${provider}|${toBase64Url(caveat.identifier)}`,
  );
}

type ParsedCaveat =
  | { type: 'first_party'; key: string; value: string; raw: string }
  | { type: 'third_party'; provider: string; identifier: string; raw: string };

function parseCaveat(raw: string): ParsedCaveat {
  const separator = raw.indexOf('=');
  if (separator <= 0) {
    return { type: 'first_party', key: raw.trim().toLowerCase(), value: '', raw };
  }

  const key = raw.slice(0, separator).trim().toLowerCase();
  const value = raw.slice(separator + 1).trim();

  if (key === 'third_party') {
    const pipe = value.indexOf('|');
    if (pipe <= 0) return { type: 'first_party', key, value, raw };

    const provider = value.slice(0, pipe).trim();
    const encodedIdentifier = value.slice(pipe + 1).trim();
    const decoded = fromBase64Url(encodedIdentifier);
    if (!provider || !decoded) {
      return { type: 'first_party', key, value, raw };
    }
    return {
      type: 'third_party',
      provider,
      identifier: decoded.toString('utf8'),
      raw,
    };
  }

  return { type: 'first_party', key, value, raw };
}

function parseTimestamp(value: string): number | null {
  if (/^\d+$/.test(value)) {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : null;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function matchesPath(pattern: string, path: string | undefined): boolean {
  if (!path) return false;
  const candidate = path.split('?')[0].replace(/\/+$/, '') || '/';
  const normalizedPattern = pattern.replace(/\/+$/, '') || '/';

  if (normalizedPattern.endsWith('*')) {
    const prefix = normalizedPattern.slice(0, -1).replace(/\/+$/, '') || '/';
    return candidate === prefix || candidate.startsWith(`${prefix}/`);
  }

  return candidate === normalizedPattern;
}

function readIdentifier(raw: string): MacaroonIdentifier | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    const identifier = parsed as Partial<MacaroonIdentifier>;
    if (
      identifier.version !== MACAROON_IDENTIFIER_VERSION ||
      typeof identifier.kid !== 'string' ||
      identifier.kid.length === 0 ||
      typeof identifier.userId !== 'string' ||
      identifier.userId.length === 0 ||
      typeof identifier.issuedAt !== 'number' ||
      !Number.isFinite(identifier.issuedAt) ||
      typeof identifier.nonce !== 'string' ||
      identifier.nonce.length === 0
    ) {
      return null;
    }
    if (identifier.email !== undefined && typeof identifier.email !== 'string') {
      return null;
    }
    if (identifier.label !== undefined && typeof identifier.label !== 'string') {
      return null;
    }
    return identifier as MacaroonIdentifier;
  } catch {
    return null;
  }
}

/** Parses a (possibly attenuated) token without verifying its signature. */
export function parseMacaroonToken(token: string): MacaroonParseResult | null {
  if (typeof token !== 'string' || !token.startsWith(TOKEN_PREFIX)) return null;

  const parts = token.slice(TOKEN_PREFIX.length).split('.');
  if (parts.length < 2) return null;

  const signaturePart = parts[parts.length - 1];
  const signature = fromBase64Url(signaturePart);
  if (!signature || signature.length !== SIGNATURE_BYTES) return null;

  const identifierPart = parts[0];
  const identifierBytes = fromBase64Url(identifierPart);
  if (!identifierBytes) return null;

  const identifier = readIdentifier(identifierBytes.toString('utf8'));
  if (!identifier) return null;

  const caveats: string[] = [];
  for (const part of parts.slice(1, -1)) {
    const decoded = fromBase64Url(part);
    if (!decoded) return null;
    const caveat = decoded.toString('utf8');
    if (!caveat || caveat.length > MAX_CAVEAT_LENGTH || /[\r\n]/.test(caveat)) {
      return null;
    }
    caveats.push(caveat);
  }

  return {
    identifierRaw: identifierBytes.toString('utf8'),
    identifier,
    caveats,
    signature: signaturePart,
  };
}

function tokenFromParts(
  identifierRaw: string,
  caveats: readonly string[],
  signature: string,
): string {
  return [
    `${TOKEN_PREFIX}${toBase64Url(identifierRaw)}`,
    ...caveats.map((caveat) => toBase64Url(caveat)),
    signature,
  ].join('.');
}

export interface MacaroonTokenServiceOptions {
  /** Root key id used by {@link mint} when none is specified. */
  primaryKid: string;
  /** kid -> root key. Keys may be rotated by keeping older ids here. */
  keyring: Record<string, MacaroonRootKey>;
}

/**
 * Mints, attenuates and verifies macaroon tokens. Verification is purely
 * cryptographic — no database or network access is performed.
 */
export class MacaroonTokenService {
  private readonly primaryKid: string;
  private readonly keyring: Map<string, Buffer>;

  constructor(options: MacaroonTokenServiceOptions) {
    if (!options.primaryKid) {
      throw new MacaroonConfigurationError('MacaroonTokenService requires a primary key id');
    }
    this.primaryKid = options.primaryKid;
    this.keyring = new Map();
    for (const [kid, key] of Object.entries(options.keyring ?? {})) {
      this.keyring.set(kid, deriveRootKey(key));
    }
    if (!this.keyring.has(this.primaryKid)) {
      throw new MacaroonConfigurationError(
        `Macaroon keyring has no root key for primary kid "${this.primaryKid}"`,
      );
    }
  }

  get primaryKeyId(): string {
    return this.primaryKid;
  }

  /** Mints a new root token. Root keys never leave the service. */
  mint(input: MacaroonMintInput): string {
    const kid = input.kid ?? this.primaryKid;
    if (!this.keyring.has(kid)) {
      throw new MacaroonConfigurationError(`Unknown macaroon root key id "${kid}"`);
    }

    const identifier: MacaroonIdentifier = {
      version: MACAROON_IDENTIFIER_VERSION,
      kid,
      userId: input.userId,
      ...(input.email ? { email: input.email } : {}),
      issuedAt: normalizeIssuedAt(input.issuedAt),
      nonce: input.nonce ?? crypto.randomBytes(16).toString('hex'),
      ...(input.label ? { label: input.label } : {}),
    };

    const identifierRaw = serializeIdentifier(identifier);
    const caveats = this.normalizeCaveats(input.caveats ?? []);
    const signature = this.signChain(identifierRaw, caveats);

    return tokenFromParts(identifierRaw, caveats, signature.toString('base64url'));
  }

  /**
   * Appends caveats to an existing token. This is deliberately possible
   * without any root key: HMAC chaining means the caller can only narrow the
   * token's authority, never widen it.
   */
  attenuate(
    token: string,
    caveats: Array<string | MacaroonThirdPartyCaveat>,
  ): string {
    const parsed = parseMacaroonToken(token);
    if (!parsed) {
      throw new MacaroonConfigurationError('Cannot attenuate a malformed macaroon');
    }
    if (caveats.length === 0) return token;

    const newCaveats = this.normalizeCaveats(caveats);

    let signature: Buffer = Buffer.from(parsed.signature, 'base64url');
    for (const caveat of newCaveats) {
      signature = hmac(signature, caveat);
    }

    return tokenFromParts(
      parsed.identifierRaw,
      [...parsed.caveats, ...newCaveats],
      signature.toString('base64url'),
    );
  }

  /** Verifies a token's signature and every caveat against `context`. */
  verify(
    token: string,
    context: MacaroonVerificationContext = {},
    options: MacaroonVerifyOptions = {},
  ): MacaroonVerificationResult {
    return this.verifyInternal(token, context, options, 0);
  }

  private verifyInternal(
    token: string,
    context: MacaroonVerificationContext,
    options: MacaroonVerifyOptions,
    depth: number,
  ): MacaroonVerificationResult {
    const parsed = parseMacaroonToken(token);
    if (!parsed) {
      return { valid: false, reason: 'malformed_token', caveats: [] };
    }

    const baseResult: MacaroonVerificationResult = {
      valid: false,
      identifier: parsed.identifier,
      caveats: parsed.caveats,
    };

    const rootKey = this.keyring.get(parsed.identifier.kid);
    if (!rootKey) {
      return { ...baseResult, reason: 'unknown_root_key', detail: `kid=${parsed.identifier.kid}` };
    }

    const signature = this.signChain(parsed.identifierRaw, parsed.caveats);
    if (!constantTimeEqual(signature, Buffer.from(parsed.signature, 'base64url'))) {
      return { ...baseResult, reason: 'invalid_signature' };
    }

    const now = options.now instanceof Date
      ? options.now.getTime()
      : options.now ?? Date.now();
    const maxDepth = options.maxDepth ?? MAX_DISCHARGE_DEPTH;

    for (const caveat of parsed.caveats) {
      const predicate = parseCaveat(caveat);
      const outcome = this.evaluateCaveat(
        predicate,
        context,
        now,
        options,
        depth,
        maxDepth,
      );

      if (!outcome.ok) {
        return { ...baseResult, reason: outcome.reason, detail: outcome.detail };
      }
    }

    return {
      valid: true,
      identifier: parsed.identifier,
      caveats: parsed.caveats,
      signature: signature.toString('hex'),
    };
  }

  private evaluateCaveat(
    predicate: ParsedCaveat,
    context: MacaroonVerificationContext,
    now: number,
    options: MacaroonVerifyOptions,
    depth: number,
    maxDepth: number,
  ): { ok: true } | { ok: false; reason: MacaroonInvalidReason; detail?: string } {
    if (predicate.type === 'third_party') {
      if (depth >= maxDepth) {
        return { ok: false, reason: 'discharge_too_deep' };
      }

      const discharges = options.discharges ?? [];
      const matching = discharges.filter((discharge) => {
        const parsedDischarge = parseMacaroonToken(discharge);
        return (
          parsedDischarge !== null &&
          parsedDischarge.identifierRaw === predicate.identifier
        );
      });

      if (matching.length === 0) {
        return {
          ok: false,
          reason: 'missing_discharge',
          detail: `provider=${predicate.provider}`,
        };
      }

      const dischargeResult = this.verifyInternal(
        matching[0],
        context,
        { ...options, discharges: [] },
        depth + 1,
      );

      if (!dischargeResult.valid) {
        return {
          ok: false,
          reason: 'invalid_discharge',
          detail: dischargeResult.reason,
        };
      }
      return { ok: true };
    }

    const { key, value } = predicate;
    const fail = (detail: string) => ({
      ok: false as const,
      reason: 'caveat_failed' as const,
      detail,
    });

    switch (key) {
      case 'wallet':
      case 'wallet_id':
        return context.walletId === value
          ? { ok: true }
          : fail(`${key} mismatch`);

      case 'user':
      case 'user_id':
        return context.userId === value ? { ok: true } : fail('user mismatch');

      case 'action':
        return context.action === value || (context.scopes ?? []).includes(value)
          ? { ok: true }
          : fail('action not granted');

      case 'scope':
        // A scoped read caveat (`wallets:read`) matches a GET request without
        // the caller having to declare the scope out of band.
        return (context.scopes ?? []).includes(value) ||
          context.action === value ||
          (context.action !== undefined && value.endsWith(`:${context.action}`))
          ? { ok: true }
          : fail('scope not granted');

      case 'method':
        return context.method?.toUpperCase() === value.toUpperCase()
          ? { ok: true }
          : fail('method mismatch');

      case 'path':
        return matchesPath(value, context.path) ? { ok: true } : fail('path mismatch');

      case 'expires':
      case 'expires_at':
      case 'expires_ms': {
        const expiresAt = parseTimestamp(value);
        if (expiresAt === null) return fail('unparsable expiry');
        return now <= expiresAt ? { ok: true } : fail('token expired');
      }

      case 'not_before':
      case 'not_before_ms': {
        const notBefore = parseTimestamp(value);
        if (notBefore === null) return fail('unparsable not_before');
        return now >= notBefore ? { ok: true } : fail('token not yet valid');
      }

      default:
        // Fail closed rather than silently ignoring a restriction we do not
        // understand.
        return { ok: false, reason: 'unknown_caveat', detail: key };
    }
  }

  private normalizeCaveats(
    caveats: ReadonlyArray<string | MacaroonThirdPartyCaveat>,
  ): string[] {
    return caveats.map((caveat) => {
      const normalized = typeof caveat === 'string' ? caveat : thirdPartyCaveat(caveat);
      if (!normalized || normalized.length > MAX_CAVEAT_LENGTH || /[\r\n]/.test(normalized)) {
        throw new MacaroonConfigurationError('Invalid caveat');
      }
      return normalized;
    });
  }

  private signChain(
    identifierRaw: string,
    caveats: readonly string[],
  ): Buffer {
    const identifier = readIdentifier(identifierRaw);
    if (!identifier) {
      throw new MacaroonConfigurationError('Invalid macaroon identifier');
    }
    const rootKey = this.keyring.get(identifier.kid);
    if (!rootKey) {
      throw new MacaroonConfigurationError(`Unknown macaroon root key id "${identifier.kid}"`);
    }

    let signature: Buffer = hmac(rootKey, identifierRaw);
    for (const caveat of caveats) {
      signature = hmac(signature, caveat);
    }
    return signature;
  }
}

/** Reads a macaroon root keyring from the documented environment config. */
export function parseMacaroonKeyring(
  env: NodeJS.ProcessEnv = process.env,
): { primaryKid: string; keyring: Record<string, MacaroonRootKey> } | null {
  if (env.MACAROON_ROOT_KEYS) {
    try {
      const parsed: unknown = JSON.parse(env.MACAROON_ROOT_KEYS);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;

      const keyring: Record<string, string> = {};
      for (const [kid, value] of Object.entries(parsed as Record<string, unknown>)) {
        if (typeof value === 'string' && value.length >= 16) {
          keyring[kid] = value;
        }
      }
      if (Object.keys(keyring).length === 0) return null;

      const primaryKid = env.MACAROON_PRIMARY_KEY_ID ?? Object.keys(keyring)[0];
      if (!keyring[primaryKid]) return null;
      return { primaryKid, keyring };
    } catch {
      return null;
    }
  }

  if (env.MACAROON_ROOT_KEY) {
    const primaryKid = env.MACAROON_PRIMARY_KEY_ID ?? 'k1';
    return { primaryKid, keyring: { [primaryKid]: env.MACAROON_ROOT_KEY } };
  }

  return null;
}

/** Returns a service from env, or null when no root key material is configured. */
export function createMacaroonServiceFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): MacaroonTokenService | null {
  const parsed = parseMacaroonKeyring(env);
  if (!parsed) return null;
  return new MacaroonTokenService(parsed);
}
