/**
 * WebAuthn / FIDO2 Hardware Security Key (YubiKey & Passkey) Second-Factor Authentication Engine (#993).
 *
 * Implements W3C WebAuthn Level 2 attestation and assertion verification using Node's
 * built-in `node:crypto` (zero external dependencies):
 * - Cryptographically random single-use registration and assertion challenges
 * - Origin-bound clientDataJSON verification (phishing-resistant)
 * - CBOR / COSE public key parsing and storage (ES256 / EdDSA / RS256)
 * - Multiple registered authenticators per user with custom nicknames
 * - Strict monotonically increasing `signCount` enforcement to detect cloned keys
 * - Step-up verification tokens for destructive actions (wallet deletion, webhook secret rotation)
 */

import crypto from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { prisma } from '../../lib/prisma';
import { redis } from '../../lib/redis';
import { createLogger } from '../../lib/logger';

const log = createLogger({ module: 'WebAuthnService' });

export const COSE_ALG_ES256 = -7;
export const COSE_ALG_EDDSA = -8;
export const COSE_ALG_RS256 = -257;

const DEFAULT_CHALLENGE_TTL_SECONDS = 300; // 5 minutes
const DEFAULT_STEP_UP_TTL_SECONDS = 300; // 5 minutes

export class WebAuthnError extends Error {
  public readonly code: string;
  public readonly statusCode: number;

  constructor(code: string, message: string, statusCode = 400) {
    super(message);
    this.name = 'WebAuthnError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

export class WebAuthnClonedKeyError extends WebAuthnError {
  public readonly credentialId: string;
  public readonly storedSignCount: number;
  public readonly receivedSignCount: number;

  constructor(credentialId: string, storedSignCount: number, receivedSignCount: number) {
    super(
      'CLONED_AUTHENTICATOR_DETECTED',
      `Authenticator signCount regression detected for credential ${credentialId}: received ${receivedSignCount} <= stored ${storedSignCount}. Possible cloned security key.`,
      403,
    );
    this.name = 'WebAuthnClonedKeyError';
    this.credentialId = credentialId;
    this.storedSignCount = storedSignCount;
    this.receivedSignCount = receivedSignCount;
  }
}

export class WebAuthnStepUpRequiredError extends WebAuthnError {
  constructor(action = 'this action') {
    super(
      'WEBAUTHN_STEP_UP_REQUIRED',
      `WebAuthn hardware key step-up verification is required before ${action}.`,
      403,
    );
    this.name = 'WebAuthnStepUpRequiredError';
  }
}

export interface StoredChallenge {
  challenge: string;
  userId: string;
  rpId: string;
  purpose: 'registration' | 'login' | 'step-up';
  expiresAt: number;
}

export interface WebAuthnCredentialRecord {
  id: string;
  userId: string;
  credentialId: string;
  nickname: string;
  publicKeyCose: string;
  algorithm: number;
  signCount: number;
  transports: string[];
  aaguid: string | null;
  backedUp: boolean;
  lastUsedAt: Date | null;
  createdAt: Date;
}

export interface ParsedAuthenticatorData {
  rpIdHash: Buffer;
  flags: {
    raw: number;
    up: boolean;
    uv: boolean;
    be: boolean;
    bs: boolean;
    at: boolean;
    ed: boolean;
  };
  signCount: number;
  aaguid?: string;
  credentialId?: string;
  credentialPublicKey?: Buffer;
}

export interface RegistrationChallengeOptions {
  userId: string;
  email: string;
  displayName?: string;
  rpId?: string;
  rpName?: string;
}

export interface AssertionChallengeOptions {
  userId: string;
  rpId?: string;
  purpose?: 'login' | 'step-up';
}

export interface VerifyRegistrationInput {
  userId: string;
  nickname: string;
  /** Base64URL-encoded clientDataJSON */
  clientDataJSON: string;
  /** Base64URL-encoded CBOR attestationObject (or raw authenticatorData if `isRawAuthData` is true) */
  attestationObject: string;
  transports?: string[];
  expectedOrigin?: string;
  expectedRpId?: string;
}

export interface VerifyAssertionInput {
  userId: string;
  /** Base64URL-encoded credential ID */
  credentialId: string;
  /** Base64URL-encoded clientDataJSON */
  clientDataJSON: string;
  /** Base64URL-encoded authenticatorData */
  authenticatorData: string;
  /** Base64URL-encoded assertion signature */
  signature: string;
  expectedOrigin?: string;
  expectedRpId?: string;
  expectedPurpose?: 'login' | 'step-up';
}

export interface WebAuthnStore {
  findByUserId(userId: string): Promise<WebAuthnCredentialRecord[]>;
  findByCredentialId(credentialId: string): Promise<WebAuthnCredentialRecord | null>;
  countByUserId(userId: string): Promise<number>;
  create(data: {
    userId: string;
    credentialId: string;
    nickname: string;
    publicKeyCose: string;
    algorithm: number;
    signCount: number;
    transports: string[];
    aaguid: string | null;
    backedUp: boolean;
  }): Promise<WebAuthnCredentialRecord>;
  updateSignCount(id: string, signCount: number, lastUsedAt: Date): Promise<WebAuthnCredentialRecord>;
  deleteByIdAndUserId(id: string, userId: string): Promise<boolean>;
}

// ── Minimal CBOR / COSE Codec (RFC 8949 / RFC 8152) ─────────────────────────

type CborValue =
  | number
  | string
  | Buffer
  | boolean
  | null
  | CborValue[]
  | Map<number | string, CborValue>;

function readCborLength(buf: Buffer, offset: number, additionalInfo: number): [number, number] {
  if (additionalInfo < 24) return [additionalInfo, offset];
  if (additionalInfo === 24) return [buf.readUInt8(offset), offset + 1];
  if (additionalInfo === 25) return [buf.readUInt16BE(offset), offset + 2];
  if (additionalInfo === 26) return [buf.readUInt32BE(offset), offset + 4];
  throw new WebAuthnError('INVALID_CBOR', `Unsupported CBOR length info: ${additionalInfo}`);
}

export function decodeCborItem(buf: Buffer, offset = 0): { value: CborValue; nextOffset: number } {
  if (offset >= buf.length) {
    throw new WebAuthnError('INVALID_CBOR', 'Unexpected end of CBOR buffer');
  }
  const initialByte = buf.readUInt8(offset);
  const majorType = initialByte >> 5;
  const additionalInfo = initialByte & 0x1f;
  let pos = offset + 1;

  if (majorType === 0) {
    const [val, next] = readCborLength(buf, pos, additionalInfo);
    return { value: val, nextOffset: next };
  }
  if (majorType === 1) {
    const [val, next] = readCborLength(buf, pos, additionalInfo);
    return { value: -1 - val, nextOffset: next };
  }
  if (majorType === 2) {
    const [len, next] = readCborLength(buf, pos, additionalInfo);
    if (next + len > buf.length) {
      throw new WebAuthnError('INVALID_CBOR', 'CBOR byte string exceeds buffer length');
    }
    return { value: buf.subarray(next, next + len), nextOffset: next + len };
  }
  if (majorType === 3) {
    const [len, next] = readCborLength(buf, pos, additionalInfo);
    if (next + len > buf.length) {
      throw new WebAuthnError('INVALID_CBOR', 'CBOR text string exceeds buffer length');
    }
    return { value: buf.subarray(next, next + len).toString('utf8'), nextOffset: next + len };
  }
  if (majorType === 4) {
    const [len, next] = readCborLength(buf, pos, additionalInfo);
    pos = next;
    const arr: CborValue[] = [];
    for (let i = 0; i < len; i++) {
      const item = decodeCborItem(buf, pos);
      arr.push(item.value);
      pos = item.nextOffset;
    }
    return { value: arr, nextOffset: pos };
  }
  if (majorType === 5) {
    const [len, next] = readCborLength(buf, pos, additionalInfo);
    pos = next;
    const map = new Map<number | string, CborValue>();
    for (let i = 0; i < len; i++) {
      const key = decodeCborItem(buf, pos);
      const val = decodeCborItem(buf, key.nextOffset);
      if (typeof key.value !== 'number' && typeof key.value !== 'string') {
        throw new WebAuthnError('INVALID_CBOR', 'CBOR map key must be number or string');
      }
      map.set(key.value, val.value);
      pos = val.nextOffset;
    }
    return { value: map, nextOffset: pos };
  }
  if (majorType === 7) {
    if (additionalInfo === 20) return { value: false, nextOffset: pos };
    if (additionalInfo === 21) return { value: true, nextOffset: pos };
    if (additionalInfo === 22) return { value: null, nextOffset: pos };
  }

  throw new WebAuthnError('INVALID_CBOR', `Unsupported CBOR major type ${majorType}`);
}

function encodeCborHeader(majorType: number, length: number): Buffer {
  const mt = majorType << 5;
  if (length < 24) return Buffer.from([mt | length]);
  if (length < 256) return Buffer.from([mt | 24, length]);
  if (length < 65536) {
    const b = Buffer.alloc(3);
    b[0] = mt | 25;
    b.writeUInt16BE(length, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = mt | 26;
  b.writeUInt32BE(length, 1);
  return b;
}

export function encodeCborValue(value: CborValue): Buffer {
  if (typeof value === 'number') {
    if (value >= 0) return encodeCborHeader(0, value);
    return encodeCborHeader(1, -1 - value);
  }
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([encodeCborHeader(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value)) {
    return Buffer.concat([encodeCborHeader(2, value.length), value]);
  }
  if (typeof value === 'boolean') {
    return Buffer.from([value ? 0xf5 : 0xf4]);
  }
  if (value === null) {
    return Buffer.from([0xf6]);
  }
  if (Array.isArray(value)) {
    return Buffer.concat([
      encodeCborHeader(4, value.length),
      ...value.map((item) => encodeCborValue(item)),
    ]);
  }
  const entries = Array.from(value.entries());
  const parts: Buffer[] = [encodeCborHeader(5, entries.length)];
  for (const [k, v] of entries) {
    parts.push(encodeCborValue(k), encodeCborValue(v));
  }
  return Buffer.concat(parts);
}

/**
 * Converts a Node public KeyObject (ES256, Ed25519, or RS256) into a CBOR-encoded COSE key.
 */
export function publicKeyToCose(publicKey: crypto.KeyObject): Buffer {
  const jwk = publicKey.export({ format: 'jwk' });
  const cose = new Map<number | string, CborValue>();

  if (jwk.kty === 'EC' && jwk.crv === 'P-256' && jwk.x && jwk.y) {
    cose.set(1, 2); // kty: EC2
    cose.set(3, COSE_ALG_ES256); // alg: ES256
    cose.set(-1, 1); // crv: P-256
    cose.set(-2, Buffer.from(jwk.x, 'base64url'));
    cose.set(-3, Buffer.from(jwk.y, 'base64url'));
    return encodeCborValue(cose);
  }
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && jwk.x) {
    cose.set(1, 1); // kty: OKP
    cose.set(3, COSE_ALG_EDDSA); // alg: EdDSA
    cose.set(-1, 6); // crv: Ed25519
    cose.set(-2, Buffer.from(jwk.x, 'base64url'));
    return encodeCborValue(cose);
  }
  if (jwk.kty === 'RSA' && jwk.n && jwk.e) {
    cose.set(1, 3); // kty: RSA
    cose.set(3, COSE_ALG_RS256); // alg: RS256
    cose.set(-1, Buffer.from(jwk.n, 'base64url'));
    cose.set(-2, Buffer.from(jwk.e, 'base64url'));
    return encodeCborValue(cose);
  }

  throw new WebAuthnError('UNSUPPORTED_KEY_TYPE', `Unsupported public key type: ${jwk.kty}`);
}

/**
 * Decodes a CBOR-encoded COSE public key into a Node `KeyObject` and COSE algorithm ID.
 */
export function coseToPublicKey(coseBuffer: Buffer): {
  publicKey: crypto.KeyObject;
  algorithm: number;
} {
  const { value } = decodeCborItem(coseBuffer, 0);
  if (!(value instanceof Map)) {
    throw new WebAuthnError('INVALID_COSE_KEY', 'COSE public key must be a CBOR map');
  }

  const kty = value.get(1);
  const alg = value.get(3);

  if (kty === 2 && alg === COSE_ALG_ES256) {
    const crv = value.get(-1);
    const x = value.get(-2);
    const y = value.get(-3);
    if (crv !== 1 || !Buffer.isBuffer(x) || !Buffer.isBuffer(y)) {
      throw new WebAuthnError('INVALID_COSE_KEY', 'Invalid ES256 COSE public key parameters');
    }
    const publicKey = crypto.createPublicKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: x.toString('base64url'),
        y: y.toString('base64url'),
      },
      format: 'jwk',
    });
    return { publicKey, algorithm: COSE_ALG_ES256 };
  }

  if (kty === 1 && alg === COSE_ALG_EDDSA) {
    const crv = value.get(-1);
    const x = value.get(-2);
    if (crv !== 6 || !Buffer.isBuffer(x)) {
      throw new WebAuthnError('INVALID_COSE_KEY', 'Invalid EdDSA COSE public key parameters');
    }
    const publicKey = crypto.createPublicKey({
      key: {
        kty: 'OKP',
        crv: 'Ed25519',
        x: x.toString('base64url'),
      },
      format: 'jwk',
    });
    return { publicKey, algorithm: COSE_ALG_EDDSA };
  }

  if (kty === 3 && alg === COSE_ALG_RS256) {
    const n = value.get(-1);
    const e = value.get(-2);
    if (!Buffer.isBuffer(n) || !Buffer.isBuffer(e)) {
      throw new WebAuthnError('INVALID_COSE_KEY', 'Invalid RS256 COSE public key parameters');
    }
    const publicKey = crypto.createPublicKey({
      key: {
        kty: 'RSA',
        n: n.toString('base64url'),
        e: e.toString('base64url'),
      },
      format: 'jwk',
    });
    return { publicKey, algorithm: COSE_ALG_RS256 };
  }

  throw new WebAuthnError(
    'UNSUPPORTED_COSE_ALGORITHM',
    `Unsupported COSE key type (${String(kty)}) or algorithm (${String(alg)})`,
  );
}

function formatAaguid(buf: Buffer): string {
  const hex = buf.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/**
 * Parses binary WebAuthn `authenticatorData` (RFC / W3C WebAuthn §6.1).
 */
export function parseAuthenticatorData(authData: Buffer): ParsedAuthenticatorData {
  if (authData.length < 37) {
    throw new WebAuthnError(
      'INVALID_AUTH_DATA',
      `Authenticator data too short: expected >= 37 bytes, got ${authData.length}`,
    );
  }

  const rpIdHash = authData.subarray(0, 32);
  const rawFlags = authData.readUInt8(32);
  const signCount = authData.readUInt32BE(33);

  const flags = {
    raw: rawFlags,
    up: Boolean(rawFlags & 0x01),
    uv: Boolean(rawFlags & 0x04),
    be: Boolean(rawFlags & 0x08),
    bs: Boolean(rawFlags & 0x10),
    at: Boolean(rawFlags & 0x40),
    ed: Boolean(rawFlags & 0x80),
  };

  if (!flags.at) {
    return { rpIdHash, flags, signCount };
  }

  if (authData.length < 55) {
    throw new WebAuthnError('INVALID_AUTH_DATA', 'Attested credential data truncated');
  }

  const aaguid = formatAaguid(authData.subarray(37, 53));
  const credIdLen = authData.readUInt16BE(53);
  const credIdEnd = 55 + credIdLen;

  if (credIdEnd > authData.length) {
    throw new WebAuthnError('INVALID_AUTH_DATA', 'Credential ID exceeds authenticatorData length');
  }

  const credentialId = authData.subarray(55, credIdEnd).toString('base64url');
  const credentialPublicKey = authData.subarray(credIdEnd);

  return {
    rpIdHash,
    flags,
    signCount,
    aaguid,
    credentialId,
    credentialPublicKey,
  };
}

// ── Prisma-backed Default Store ─────────────────────────────────────────────

const defaultPrismaStore: WebAuthnStore = {
  async findByUserId(userId) {
    return prisma.webAuthnCredential.findMany({
      where: { userId },
      orderBy: { createdAt: 'asc' },
    });
  },
  async findByCredentialId(credentialId) {
    return prisma.webAuthnCredential.findUnique({
      where: { credentialId },
    });
  },
  async countByUserId(userId) {
    return prisma.webAuthnCredential.count({
      where: { userId },
    });
  },
  async create(data) {
    return prisma.webAuthnCredential.create({ data });
  },
  async updateSignCount(id, signCount, lastUsedAt) {
    return prisma.webAuthnCredential.update({
      where: { id },
      data: { signCount, lastUsedAt },
    });
  },
  async deleteByIdAndUserId(id, userId) {
    const deleted = await prisma.webAuthnCredential.deleteMany({
      where: { id, userId },
    });
    return deleted.count > 0;
  },
};

// ── WebAuthnService ─────────────────────────────────────────────────────────

export class WebAuthnService {
  private readonly store: WebAuthnStore;
  private readonly redisClient: typeof redis | null;
  private readonly defaultRpId: string;
  private readonly defaultRpName: string;
  private readonly defaultOrigin: string;
  private readonly challengeTtlSeconds: number;
  private readonly stepUpTtlSeconds: number;
  private readonly memoryChallenges = new Map<string, StoredChallenge>();
  private readonly memoryStepUpTokens = new Map<string, { userId: string; expiresAt: number }>();

  constructor(options?: {
    store?: WebAuthnStore;
    redisClient?: typeof redis | null;
    rpId?: string;
    rpName?: string;
    origin?: string;
    challengeTtlSeconds?: number;
    stepUpTtlSeconds?: number;
  }) {
    this.store = options?.store ?? defaultPrismaStore;
    this.redisClient = options?.redisClient === undefined ? redis : options.redisClient;
    this.defaultRpId = options?.rpId ?? process.env.WEBAUTHN_RP_ID ?? 'localhost';
    this.defaultRpName = options?.rpName ?? process.env.WEBAUTHN_RP_NAME ?? 'Stellar Alerts';
    this.defaultOrigin =
      options?.origin ?? process.env.WEBAUTHN_ORIGIN ?? `https://${this.defaultRpId}`;
    this.challengeTtlSeconds = options?.challengeTtlSeconds ?? DEFAULT_CHALLENGE_TTL_SECONDS;
    this.stepUpTtlSeconds = options?.stepUpTtlSeconds ?? DEFAULT_STEP_UP_TTL_SECONDS;
  }

  /**
   * Generates a single-use WebAuthn registration challenge (PublicKeyCredentialCreationOptions).
   */
  public async generateRegistrationChallenge(options: RegistrationChallengeOptions) {
    const rpId = options.rpId ?? this.defaultRpId;
    const rpName = options.rpName ?? this.defaultRpName;
    const challenge = crypto.randomBytes(32).toString('base64url');
    const existingCredentials = await this.store.findByUserId(options.userId);

    await this.saveChallenge({
      challenge,
      userId: options.userId,
      rpId,
      purpose: 'registration',
      expiresAt: Date.now() + this.challengeTtlSeconds * 1000,
    });

    return {
      challenge,
      rp: { id: rpId, name: rpName },
      user: {
        id: Buffer.from(options.userId, 'utf8').toString('base64url'),
        name: options.email,
        displayName: options.displayName ?? options.email,
      },
      pubKeyCredParams: [
        { type: 'public-key' as const, alg: COSE_ALG_ES256 },
        { type: 'public-key' as const, alg: COSE_ALG_EDDSA },
        { type: 'public-key' as const, alg: COSE_ALG_RS256 },
      ],
      timeout: this.challengeTtlSeconds * 1000,
      attestation: 'none' as const,
      excludeCredentials: existingCredentials.map((cred) => ({
        type: 'public-key' as const,
        id: cred.credentialId,
        transports: cred.transports,
      })),
      authenticatorSelection: {
        residentKey: 'preferred' as const,
        userVerification: 'preferred' as const,
      },
    };
  }

  /**
   * Generates a single-use WebAuthn assertion challenge (PublicKeyCredentialRequestOptions)
   * for either login or step-up verification before destructive operations.
   */
  public async generateAssertionChallenge(options: AssertionChallengeOptions) {
    const rpId = options.rpId ?? this.defaultRpId;
    const purpose = options.purpose ?? 'login';
    const credentials = await this.store.findByUserId(options.userId);

    if (credentials.length === 0) {
      throw new WebAuthnError(
        'NO_CREDENTIALS_REGISTERED',
        'No FIDO2 / WebAuthn security keys are registered for this account.',
        400,
      );
    }

    const challenge = crypto.randomBytes(32).toString('base64url');
    await this.saveChallenge({
      challenge,
      userId: options.userId,
      rpId,
      purpose,
      expiresAt: Date.now() + this.challengeTtlSeconds * 1000,
    });

    return {
      challenge,
      rpId,
      timeout: this.challengeTtlSeconds * 1000,
      userVerification: 'preferred' as const,
      purpose,
      allowCredentials: credentials.map((cred) => ({
        type: 'public-key' as const,
        id: cred.credentialId,
        transports: cred.transports,
      })),
    };
  }

  /**
   * Verifies a WebAuthn registration attestation and stores the COSE public key
   * under the user's account with the given custom nickname.
   */
  public async verifyRegistrationAttestation(
    input: VerifyRegistrationInput,
  ): Promise<WebAuthnCredentialRecord> {
    const nickname = input.nickname.trim();
    if (!nickname) {
      throw new WebAuthnError('INVALID_NICKNAME', 'Authenticator nickname is required.');
    }

    const clientDataBuf = Buffer.from(input.clientDataJSON, 'base64url');
    const clientData = this.parseClientDataJSON(clientDataBuf);

    if (clientData.type !== 'webauthn.create') {
      throw new WebAuthnError(
        'INVALID_CLIENT_DATA_TYPE',
        `Expected clientData type "webauthn.create", received "${clientData.type}"`,
      );
    }

    const expectedOrigin = input.expectedOrigin ?? this.defaultOrigin;
    if (clientData.origin !== expectedOrigin) {
      throw new WebAuthnError(
        'ORIGIN_MISMATCH',
        `Origin mismatch: expected "${expectedOrigin}", received "${clientData.origin}"`,
        403,
      );
    }

    const storedChallenge = await this.consumeChallenge(clientData.challenge);
    if (
      !storedChallenge ||
      storedChallenge.userId !== input.userId ||
      storedChallenge.purpose !== 'registration'
    ) {
      throw new WebAuthnError('INVALID_CHALLENGE', 'Registration challenge is invalid or expired.');
    }

    const expectedRpId = input.expectedRpId ?? storedChallenge.rpId;

    // Decode CBOR attestationObject ({ fmt, authData, attStmt })
    const attestationBuf = Buffer.from(input.attestationObject, 'base64url');
    const decodedAtt = decodeCborItem(attestationBuf, 0).value;
    if (!(decodedAtt instanceof Map)) {
      throw new WebAuthnError('INVALID_ATTESTATION', 'Attestation object must be a CBOR map');
    }
    const authDataRaw = decodedAtt.get('authData');
    if (!Buffer.isBuffer(authDataRaw)) {
      throw new WebAuthnError('INVALID_ATTESTATION', 'Attestation object missing authData bytes');
    }

    const authData = parseAuthenticatorData(authDataRaw);
    this.verifyRpIdHash(authData.rpIdHash, expectedRpId);

    if (!authData.flags.up) {
      throw new WebAuthnError('USER_NOT_PRESENT', 'Authenticator did not assert User Present (UP)');
    }
    if (!authData.flags.at || !authData.credentialId || !authData.credentialPublicKey) {
      throw new WebAuthnError(
        'MISSING_ATTESTED_CREDENTIAL',
        'Authenticator data missing attested credential public key',
      );
    }

    // Validate COSE key cryptographically before persisting
    const { algorithm } = coseToPublicKey(authData.credentialPublicKey);

    const existing = await this.store.findByCredentialId(authData.credentialId);
    if (existing) {
      throw new WebAuthnError(
        'CREDENTIAL_ALREADY_REGISTERED',
        'This security key credential is already registered.',
        409,
      );
    }

    const saved = await this.store.create({
      userId: input.userId,
      credentialId: authData.credentialId,
      nickname,
      publicKeyCose: authData.credentialPublicKey.toString('base64url'),
      algorithm,
      signCount: authData.signCount,
      transports: input.transports ?? [],
      aaguid: authData.aaguid ?? null,
      backedUp: authData.flags.bs,
    });

    log.info(
      { userId: input.userId, credentialId: saved.credentialId, nickname, algorithm },
      'Registered WebAuthn hardware security key',
    );

    return saved;
  }

  /**
   * Verifies a cryptographic WebAuthn assertion signature and strictly enforces
   * monotonically increasing `signCount` to reject cloned authenticators.
   */
  public async verifyAssertion(input: VerifyAssertionInput): Promise<{
    verified: true;
    credentialId: string;
    nickname: string;
    signCount: number;
    purpose: 'login' | 'step-up';
    stepUpToken: string;
  }> {
    const clientDataBuf = Buffer.from(input.clientDataJSON, 'base64url');
    const clientData = this.parseClientDataJSON(clientDataBuf);

    if (clientData.type !== 'webauthn.get') {
      throw new WebAuthnError(
        'INVALID_CLIENT_DATA_TYPE',
        `Expected clientData type "webauthn.get", received "${clientData.type}"`,
      );
    }

    const expectedOrigin = input.expectedOrigin ?? this.defaultOrigin;
    if (clientData.origin !== expectedOrigin) {
      throw new WebAuthnError(
        'ORIGIN_MISMATCH',
        `Origin mismatch: expected "${expectedOrigin}", received "${clientData.origin}"`,
        403,
      );
    }

    const storedChallenge = await this.consumeChallenge(clientData.challenge);
    if (
      !storedChallenge ||
      storedChallenge.userId !== input.userId ||
      storedChallenge.purpose === 'registration'
    ) {
      throw new WebAuthnError('INVALID_CHALLENGE', 'Assertion challenge is invalid or expired.');
    }
    if (input.expectedPurpose && storedChallenge.purpose !== input.expectedPurpose) {
      throw new WebAuthnError(
        'CHALLENGE_PURPOSE_MISMATCH',
        `Expected "${input.expectedPurpose}" challenge, received "${storedChallenge.purpose}"`,
      );
    }

    const credential = await this.store.findByCredentialId(input.credentialId);
    if (!credential || credential.userId !== input.userId) {
      throw new WebAuthnError('UNKNOWN_CREDENTIAL', 'WebAuthn credential not found for user.', 404);
    }

    const authDataBuf = Buffer.from(input.authenticatorData, 'base64url');
    const authData = parseAuthenticatorData(authDataBuf);

    const expectedRpId = input.expectedRpId ?? storedChallenge.rpId;
    this.verifyRpIdHash(authData.rpIdHash, expectedRpId);

    if (!authData.flags.up) {
      throw new WebAuthnError('USER_NOT_PRESENT', 'Authenticator did not assert User Present (UP)');
    }

    // Verify cryptographic signature over authenticatorData || SHA-256(clientDataJSON)
    const clientDataHash = crypto.createHash('sha256').update(clientDataBuf).digest();
    const signedData = Buffer.concat([authDataBuf, clientDataHash]);
    const signatureBuf = Buffer.from(input.signature, 'base64url');
    const { publicKey, algorithm } = coseToPublicKey(
      Buffer.from(credential.publicKeyCose, 'base64url'),
    );

    const isSignatureValid = this.verifySignature(publicKey, algorithm, signedData, signatureBuf);
    if (!isSignatureValid) {
      throw new WebAuthnError('INVALID_SIGNATURE', 'WebAuthn cryptographic signature verification failed.', 401);
    }

    // Strict anti-cloning check: signCount MUST be strictly greater than the previously stored value.
    if (authData.signCount <= credential.signCount) {
      log.warn(
        {
          userId: input.userId,
          credentialId: credential.credentialId,
          storedSignCount: credential.signCount,
          receivedSignCount: authData.signCount,
        },
        '🚨 [SECURITY] Cloned WebAuthn authenticator detected (signCount regression/replay)',
      );
      throw new WebAuthnClonedKeyError(
        credential.credentialId,
        credential.signCount,
        authData.signCount,
      );
    }

    await this.store.updateSignCount(credential.id, authData.signCount, new Date());

    const stepUpToken = await this.issueStepUpToken(input.userId);

    return {
      verified: true,
      credentialId: credential.credentialId,
      nickname: credential.nickname,
      signCount: authData.signCount,
      purpose: storedChallenge.purpose,
      stepUpToken,
    };
  }

  /**
   * Lists all registered WebAuthn credentials for a user (omitting raw key internals).
   */
  public async listCredentials(userId: string) {
    const records = await this.store.findByUserId(userId);
    return records.map((cred) => ({
      id: cred.id,
      credentialId: cred.credentialId,
      nickname: cred.nickname,
      algorithm: cred.algorithm,
      signCount: cred.signCount,
      transports: cred.transports,
      aaguid: cred.aaguid,
      backedUp: cred.backedUp,
      lastUsedAt: cred.lastUsedAt,
      createdAt: cred.createdAt,
    }));
  }

  /**
   * Deletes a registered WebAuthn credential belonging to the user.
   */
  public async deleteCredential(userId: string, id: string): Promise<boolean> {
    return this.store.deleteByIdAndUserId(id, userId);
  }

  /**
   * Enforces WebAuthn step-up verification before destructive actions (e.g. wallet deletion
   * or webhook signing secret rotation).
   *
   * Users with no registered WebAuthn keys pass through; users with >= 1 registered key
   * must supply a valid single-use step-up proof token obtained from a recent assertion.
   */
  public async verifyStepUpAccess(
    userId: string,
    stepUpToken?: string | null,
    action?: string,
  ): Promise<{ required: boolean; verified: boolean }> {
    const credentialCount = await this.store.countByUserId(userId);
    if (credentialCount === 0) {
      return { required: false, verified: true };
    }

    if (!stepUpToken) {
      throw new WebAuthnStepUpRequiredError(action);
    }

    const valid = await this.consumeStepUpToken(userId, stepUpToken);
    if (!valid) {
      throw new WebAuthnStepUpRequiredError(action);
    }

    return { required: true, verified: true };
  }

  // ── Internal Helpers ────────────────────────────────────────────────────

  private verifySignature(
    publicKey: crypto.KeyObject,
    algorithm: number,
    data: Buffer,
    signature: Buffer,
  ): boolean {
    try {
      if (algorithm === COSE_ALG_EDDSA) {
        return crypto.verify(null, data, publicKey, signature);
      }
      if (algorithm === COSE_ALG_ES256 || algorithm === COSE_ALG_RS256) {
        return crypto.verify('sha256', data, publicKey, signature);
      }
      return false;
    } catch {
      return false;
    }
  }

  private verifyRpIdHash(rpIdHash: Buffer, expectedRpId: string): void {
    const expectedHash = crypto.createHash('sha256').update(expectedRpId).digest();
    if (rpIdHash.length !== expectedHash.length || !crypto.timingSafeEqual(rpIdHash, expectedHash)) {
      throw new WebAuthnError(
        'RP_ID_HASH_MISMATCH',
        `Relying Party ID hash mismatch for rpId "${expectedRpId}"`,
        403,
      );
    }
  }

  private parseClientDataJSON(buf: Buffer): { type: string; challenge: string; origin: string } {
    try {
      const parsed = JSON.parse(buf.toString('utf8')) as Record<string, unknown>;
      if (
        typeof parsed.type !== 'string' ||
        typeof parsed.challenge !== 'string' ||
        typeof parsed.origin !== 'string'
      ) {
        throw new WebAuthnError('INVALID_CLIENT_DATA', 'clientDataJSON missing required fields');
      }
      return {
        type: parsed.type,
        challenge: parsed.challenge,
        origin: parsed.origin,
      };
    } catch (err) {
      if (err instanceof WebAuthnError) throw err;
      throw new WebAuthnError('INVALID_CLIENT_DATA', 'Malformed clientDataJSON');
    }
  }

  private async saveChallenge(record: StoredChallenge): Promise<void> {
    const key = `webauthn:challenge:${record.challenge}`;
    this.memoryChallenges.set(record.challenge, record);
    if (this.redisClient) {
      try {
        await this.redisClient.set(key, JSON.stringify(record), 'EX', this.challengeTtlSeconds);
      } catch {
        // Fallback to in-memory map
      }
    }
  }

  private async consumeChallenge(challenge: string): Promise<StoredChallenge | null> {
    const key = `webauthn:challenge:${challenge}`;
    let record: StoredChallenge | null = null;

    if (this.redisClient) {
      try {
        const raw = await this.redisClient.get(key);
        if (raw) {
          await this.redisClient.del(key);
          record = JSON.parse(raw) as StoredChallenge;
        }
      } catch {
        // Fallback to in-memory map
      }
    }

    if (!record) {
      const mem = this.memoryChallenges.get(challenge);
      if (mem) {
        record = mem;
      }
    }
    this.memoryChallenges.delete(challenge);

    if (!record || record.expiresAt < Date.now()) {
      return null;
    }

    return record;
  }

  private async issueStepUpToken(userId: string): Promise<string> {
    const token = crypto.randomBytes(32).toString('base64url');
    const expiresAt = Date.now() + this.stepUpTtlSeconds * 1000;
    this.memoryStepUpTokens.set(token, { userId, expiresAt });

    if (this.redisClient) {
      try {
        await this.redisClient.set(
          `webauthn:stepup:${token}`,
          JSON.stringify({ userId, expiresAt }),
          'EX',
          this.stepUpTtlSeconds,
        );
      } catch {
        // Fallback to in-memory map
      }
    }

    return token;
  }

  private async consumeStepUpToken(userId: string, token: string): Promise<boolean> {
    const key = `webauthn:stepup:${token}`;
    let record: { userId: string; expiresAt: number } | null = null;

    if (this.redisClient) {
      try {
        const raw = await this.redisClient.get(key);
        if (raw) {
          await this.redisClient.del(key);
          record = JSON.parse(raw) as { userId: string; expiresAt: number };
        }
      } catch {
        // Fallback to in-memory map
      }
    }

    if (!record) {
      record = this.memoryStepUpTokens.get(token) ?? null;
    }
    this.memoryStepUpTokens.delete(token);

    if (!record || record.userId !== userId || record.expiresAt < Date.now()) {
      return false;
    }
    return true;
  }
}

export const webAuthnService = new WebAuthnService();

/**
 * Fastify preHandler factory that enforces WebAuthn step-up verification before
 * destructive operations (wallet deletion, webhook signing secret rotation).
 */
export function requireWebAuthnStepUp(action: string, service: WebAuthnService = webAuthnService) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user?.id;
    if (!userId) return;

    const rawHeader = request.headers['x-webauthn-step-up'];
    const token = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader;

    try {
      await service.verifyStepUpAccess(userId, token, action);
    } catch (err: unknown) {
      if (err instanceof WebAuthnStepUpRequiredError) {
        return reply.status(err.statusCode).send({
          error: err.code,
          message: err.message,
        });
      }
      throw err;
    }
  };
}
