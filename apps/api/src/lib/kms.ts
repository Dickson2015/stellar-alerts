import crypto from 'crypto';

/**
 * Envelope encryption for webhook signing secrets (#927).
 *
 * Compliance frameworks (SOC 2, ISO 27001) forbid keeping plaintext
 * cryptographic secrets — or a single long-lived static encryption key — on an
 * application server. This module implements *envelope encryption*:
 *
 *   1. a fresh 256-bit data key is generated per secret,
 *   2. the data key encrypts the secret with AES-256-GCM in memory,
 *   3. the data key is wrapped (encrypted) by a KMS master key — AWS KMS,
 *      HashiCorp Vault Transit, or the local AES fallback below,
 *   4. only the wrapped data key is persisted next to the ciphertext.
 *
 * The stored envelope is a compact string:
 *
 *   `kms:v1:<provider>:<keyId>:<wrappedKey>:<iv>:<authTag>:<ciphertext>`
 *
 * Every component except the provider name and version is base64url, so an
 * ARN or Vault path containing `:` survives a round trip. Envelopes record the
 * provider and master key id, which lets {@link KmsKeyService.rotateEnvelope}
 * recognise ciphertext produced by an older master key and re-wrap it without
 * touching the plaintext.
 *
 * Provider adapters take injected SDK clients (the same pattern as
 * `utils/kms-signer.ts`) so the API never depends on a specific cloud SDK and
 * unit tests can use a fake KMS without network access.
 */

export const KMS_ENVELOPE_VERSION = 1;
export const KMS_ENVELOPE_PREFIX = 'kms';
export const KMS_ENVELOPE_ALGORITHM = 'aes-256-gcm';
export const KMS_ENVELOPE_INFO = 'stellar-alerts-kms-envelope-v1';
export const KMS_DATA_KEY_BYTES = 32;
export const KMS_GCM_IV_BYTES = 12;

export type KmsEnvelopeProviderId = 'aws' | 'vault' | 'local';

export interface DataKeyEnvelope {
  /** 32-byte plaintext data key. Never persisted. */
  plaintextKey: Buffer;
  /** Opaque provider-specific wrapping of the data key, safe to store. */
  wrappedKey: string;
  /** Master key id that wrapped this data key. */
  keyId: string;
}

export interface KmsEnvelopeProvider {
  readonly providerId: KmsEnvelopeProviderId;
  /** Master key id used for newly produced envelopes. */
  readonly keyId: string;
  generateDataKey(context?: Record<string, string>): Promise<DataKeyEnvelope>;
  unwrapDataKey(wrappedKey: string, context?: Record<string, string>): Promise<Buffer>;
  /**
   * Optional hook for providers that can decrypt more than one key id (the
   * local provider keeps older master-key versions in a keyring). Defaults to
   * an exact `keyId` comparison.
   */
  acceptsKeyId?(keyId: string): boolean;
}

export class KmsEnvelopeError extends Error {
  readonly code: string;

  constructor(message: string, code = 'KMS_ENVELOPE_ERROR') {
    super(message);
    this.name = 'KmsEnvelopeError';
    this.code = code;
  }
}

export class KmsConfigurationError extends KmsEnvelopeError {
  constructor(message: string) {
    super(message, 'KMS_CONFIGURATION_ERROR');
    this.name = 'KmsConfigurationError';
  }
}

interface ParsedEnvelope {
  version: number;
  providerId: KmsEnvelopeProviderId;
  keyId: string;
  wrappedKey: string;
  iv: Buffer;
  authTag: Buffer;
  ciphertext: Buffer;
}

function toBase64Url(value: Buffer | string): string {
  return Buffer.from(value).toString('base64url');
}

function fromBase64Url(value: string): Buffer {
  return Buffer.from(value, 'base64url');
}

function assertProviderId(value: string): KmsEnvelopeProviderId {
  if (value === 'aws' || value === 'vault' || value === 'local') {
    return value;
  }
  throw new KmsEnvelopeError(`Unknown KMS envelope provider "${value}"`, 'KMS_ENVELOPE_UNKNOWN_PROVIDER');
}

function parseEnvelope(envelope: string): ParsedEnvelope {
  if (typeof envelope !== 'string' || envelope.length === 0) {
    throw new KmsEnvelopeError('Encrypted secret must be a non-empty string', 'KMS_ENVELOPE_MALFORMED');
  }

  const parts = envelope.split(':');
  if (parts.length !== 8 || parts[0] !== KMS_ENVELOPE_PREFIX) {
    throw new KmsEnvelopeError('Invalid KMS envelope format', 'KMS_ENVELOPE_MALFORMED');
  }

  const version = Number(parts[1].replace(/^v/, ''));
  if (!Number.isInteger(version) || version < 1) {
    throw new KmsEnvelopeError('Invalid KMS envelope version', 'KMS_ENVELOPE_MALFORMED');
  }

  const iv = fromBase64Url(parts[5]);
  const authTag = fromBase64Url(parts[6]);
  if (iv.length !== KMS_GCM_IV_BYTES || authTag.length !== 16) {
    throw new KmsEnvelopeError('Invalid KMS envelope cipher parameters', 'KMS_ENVELOPE_MALFORMED');
  }

  return {
    version,
    providerId: assertProviderId(parts[2]),
    keyId: fromBase64Url(parts[3]).toString('utf8'),
    wrappedKey: fromBase64Url(parts[4]).toString('utf8'),
    iv,
    authTag,
    ciphertext: fromBase64Url(parts[7]),
  };
}

/** True when `value` looks like an envelope produced by this module. */
export function isKmsEnvelope(value: unknown): value is string {
  if (typeof value !== 'string' || !value.startsWith(`${KMS_ENVELOPE_PREFIX}:v`)) {
    return false;
  }
  try {
    parseEnvelope(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Local AES-256-GCM master key used when no cloud KMS is configured. The KEK
 * is derived with HKDF-SHA256, so the raw environment variable is never used
 * directly as an encryption key.
 *
 * A keyring of older versions is supported so a master-key rotation does not
 * make existing ciphertext undecryptable; run
 * {@link KmsKeyService.rotateEnvelope} over stored rows to move them onto the
 * current version.
 */
export class LocalEnvelopeProvider implements KmsEnvelopeProvider {
  readonly providerId = 'local' as const;
  readonly keyId: string;
  private readonly version: number;
  private readonly keyring: Map<number, Buffer>;

  constructor(options: {
    masterKey: string;
    version?: number;
    oldKeys?: Record<number, string>;
  }) {
    if (!options.masterKey) {
      throw new KmsConfigurationError('Local KMS envelope provider requires a master key');
    }

    this.version = options.version ?? 1;
    if (!Number.isInteger(this.version) || this.version < 1) {
      throw new KmsConfigurationError('Local KMS envelope key version must be a positive integer');
    }

    this.keyId = `local/v${this.version}`;
    this.keyring = new Map();
    for (const [rawVersion, key] of Object.entries(options.oldKeys ?? {})) {
      const version = Number(rawVersion);
      if (!Number.isInteger(version) || version < 1 || !key) continue;
      this.keyring.set(version, this.deriveKek(key, version));
    }
    this.keyring.set(this.version, this.deriveKek(options.masterKey, this.version));
  }

  private deriveKek(masterKey: string, version: number): Buffer {
    return Buffer.from(
      crypto.hkdfSync(
        'sha256',
        Buffer.from(masterKey, 'utf8'),
        Buffer.from(`stellar-alerts-kms-local:v${version}`, 'utf8'),
        Buffer.from(KMS_ENVELOPE_INFO, 'utf8'),
        32,
      ),
    );
  }

  acceptsKeyId(keyId: string): boolean {
    const match = /^local\/v(\d+)$/.exec(keyId);
    if (!match) return false;
    return this.keyring.has(Number(match[1]));
  }

  async generateDataKey(): Promise<DataKeyEnvelope> {
    const plaintextKey = crypto.randomBytes(KMS_DATA_KEY_BYTES);
    return {
      plaintextKey,
      wrappedKey: this.wrapDataKey(plaintextKey),
      keyId: this.keyId,
    };
  }

  private wrapDataKey(dataKey: Buffer): string {
    const kek = this.keyring.get(this.version);
    if (!kek) {
      throw new KmsConfigurationError(`No local KMS master key for version ${this.version}`);
    }
    const iv = crypto.randomBytes(KMS_GCM_IV_BYTES);
    const cipher = crypto.createCipheriv(KMS_ENVELOPE_ALGORITHM, kek, iv);
    const ciphertext = Buffer.concat([cipher.update(dataKey), cipher.final()]);
    return [
      `v${this.version}`,
      toBase64Url(iv),
      toBase64Url(cipher.getAuthTag()),
      toBase64Url(ciphertext),
    ].join(':');
  }

  async unwrapDataKey(wrappedKey: string): Promise<Buffer> {
    const [versionPart, ivPart, tagPart, ciphertextPart] = wrappedKey.split(':');
    const version = Number((versionPart ?? '').replace(/^v/, ''));
    const kek = this.keyring.get(version);

    if (!kek) {
      throw new KmsEnvelopeError(
        `No local KMS master key for wrapped data key version ${versionPart}`,
        'KMS_ENVELOPE_UNKNOWN_KEY',
      );
    }

    try {
      const decipher = crypto.createDecipheriv(
        KMS_ENVELOPE_ALGORITHM,
        kek,
        fromBase64Url(ivPart ?? ''),
      );
      decipher.setAuthTag(fromBase64Url(tagPart ?? ''));
      return Buffer.concat([
        decipher.update(fromBase64Url(ciphertextPart ?? '')),
        decipher.final(),
      ]);
    } catch {
      throw new KmsEnvelopeError(
        'Local data key could not be unwrapped',
        'KMS_ENVELOPE_DECRYPT_FAILED',
      );
    }
  }
}

/** AWS KMS GenerateDataKey/Decrypt command shapes (compatible with @aws-sdk/client-kms). */
export interface AwsKmsEnvelopeClientLike {
  generateDataKey(params: {
    KeyId: string;
    KeySpec?: 'AES_256';
    EncryptionContext?: Record<string, string>;
  }): Promise<{ Plaintext?: Uint8Array; CiphertextBlob?: Uint8Array }>;
  decrypt(params: {
    CiphertextBlob: Uint8Array;
    KeyId?: string;
    EncryptionContext?: Record<string, string>;
  }): Promise<{ Plaintext?: Uint8Array }>;
}

export class AwsKmsEnvelopeProvider implements KmsEnvelopeProvider {
  readonly providerId = 'aws' as const;

  constructor(
    private readonly client: AwsKmsEnvelopeClientLike,
    readonly keyId: string,
  ) {
    if (!keyId) {
      throw new KmsConfigurationError('AWS KMS envelope provider requires a master key id');
    }
  }

  acceptsKeyId(keyId: string): boolean {
    return keyId === this.keyId;
  }

  async generateDataKey(context?: Record<string, string>): Promise<DataKeyEnvelope> {
    const result = await this.client.generateDataKey({
      KeyId: this.keyId,
      KeySpec: 'AES_256',
      ...(context && Object.keys(context).length > 0 ? { EncryptionContext: context } : {}),
    });

    if (!result.Plaintext || !result.CiphertextBlob) {
      throw new KmsEnvelopeError(
        'AWS KMS GenerateDataKey returned no data key',
        'KMS_ENVELOPE_PROVIDER_ERROR',
      );
    }

    return {
      plaintextKey: Buffer.from(result.Plaintext),
      // Base64 (not base64url): the outer envelope encoding handles the
      // separator-safe representation.
      wrappedKey: Buffer.from(result.CiphertextBlob).toString('base64'),
      keyId: this.keyId,
    };
  }

  async unwrapDataKey(wrappedKey: string, context?: Record<string, string>): Promise<Buffer> {
    const result = await this.client.decrypt({
      CiphertextBlob: Buffer.from(wrappedKey, 'base64'),
      KeyId: this.keyId,
      ...(context && Object.keys(context).length > 0 ? { EncryptionContext: context } : {}),
    });

    if (!result.Plaintext) {
      throw new KmsEnvelopeError(
        'AWS KMS Decrypt returned no plaintext data key',
        'KMS_ENVELOPE_PROVIDER_ERROR',
      );
    }
    return Buffer.from(result.Plaintext);
  }
}

/** HashiCorp Vault Transit `datakey`/`decrypt` shapes. Base64 in, base64 out. */
export interface VaultTransitEnvelopeClientLike {
  generateDataKey(
    keyName: string,
    context?: Record<string, string>,
  ): Promise<{ plaintext?: string; ciphertext?: string }>;
  decrypt(
    keyName: string,
    ciphertext: string,
    context?: Record<string, string>,
  ): Promise<{ plaintext?: string }>;
}

export class VaultTransitEnvelopeProvider implements KmsEnvelopeProvider {
  readonly providerId = 'vault' as const;

  constructor(
    private readonly client: VaultTransitEnvelopeClientLike,
    readonly keyId: string,
  ) {
    if (!keyId) {
      throw new KmsConfigurationError('Vault Transit envelope provider requires a key name');
    }
  }

  acceptsKeyId(keyId: string): boolean {
    return keyId === this.keyId;
  }

  async generateDataKey(context?: Record<string, string>): Promise<DataKeyEnvelope> {
    const result = await this.client.generateDataKey(this.keyId, context);
    if (!result.plaintext || !result.ciphertext) {
      throw new KmsEnvelopeError(
        'Vault Transit datakey returned no data key',
        'KMS_ENVELOPE_PROVIDER_ERROR',
      );
    }
    return {
      plaintextKey: Buffer.from(result.plaintext, 'base64'),
      wrappedKey: result.ciphertext,
      keyId: this.keyId,
    };
  }

  async unwrapDataKey(wrappedKey: string, context?: Record<string, string>): Promise<Buffer> {
    const result = await this.client.decrypt(this.keyId, wrappedKey, context);
    if (!result.plaintext) {
      throw new KmsEnvelopeError(
        'Vault Transit decrypt returned no plaintext data key',
        'KMS_ENVELOPE_PROVIDER_ERROR',
      );
    }
    return Buffer.from(result.plaintext, 'base64');
  }
}

export interface KmsKeyServiceOptions {
  provider: KmsEnvelopeProvider;
  /**
   * Providers used only to decrypt envelopes produced by an older master key
   * or a different backend. Never used to encrypt.
   */
  decryptionProviders?: KmsEnvelopeProvider[];
}

export interface KmsRotationResult {
  envelope: string;
  rotated: boolean;
}

/**
 * Encrypts/decrypts webhook signing secrets with a KMS-wrapped data key and
 * transparently re-encrypts envelopes after a master-key rotation.
 */
export class KmsKeyService {
  private readonly provider: KmsEnvelopeProvider;
  private readonly decryptionProviders: KmsEnvelopeProvider[];

  constructor(options: KmsKeyServiceOptions) {
    if (!options.provider) {
      throw new KmsConfigurationError('KmsKeyService requires an envelope provider');
    }
    this.provider = options.provider;
    this.decryptionProviders = [...(options.decryptionProviders ?? [])];
  }

  get providerId(): KmsEnvelopeProviderId {
    return this.provider.providerId;
  }

  get keyId(): string {
    return this.provider.keyId;
  }

  /** Encrypts a secret and returns the persisted envelope string. */
  async encryptSecret(
    plaintext: string,
    context?: Record<string, string>,
  ): Promise<string> {
    if (typeof plaintext !== 'string') {
      throw new KmsEnvelopeError('Secret must be a string', 'KMS_ENVELOPE_INVALID_INPUT');
    }

    const dataKey = await this.provider.generateDataKey(context);
    if (dataKey.plaintextKey.length !== KMS_DATA_KEY_BYTES) {
      throw new KmsEnvelopeError(
        'KMS provider returned a data key with an unexpected length',
        'KMS_ENVELOPE_PROVIDER_ERROR',
      );
    }

    try {
      const iv = crypto.randomBytes(KMS_GCM_IV_BYTES);
      const cipher = crypto.createCipheriv(KMS_ENVELOPE_ALGORITHM, dataKey.plaintextKey, iv);
      const ciphertext = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final(),
      ]);

      return [
        KMS_ENVELOPE_PREFIX,
        `v${KMS_ENVELOPE_VERSION}`,
        this.provider.providerId,
        toBase64Url(dataKey.keyId || this.provider.keyId),
        toBase64Url(dataKey.wrappedKey),
        toBase64Url(iv),
        toBase64Url(cipher.getAuthTag()),
        toBase64Url(ciphertext),
      ].join(':');
    } finally {
      // Best-effort scrub; Node buffers are not guaranteed to be zeroed by GC.
      dataKey.plaintextKey.fill(0);
    }
  }

  /** Decrypts an envelope produced by {@link encryptSecret}. */
  async decryptSecret(
    envelope: string,
    context?: Record<string, string>,
  ): Promise<string> {
    const parsed = parseEnvelope(envelope);
    if (parsed.version !== KMS_ENVELOPE_VERSION) {
      throw new KmsEnvelopeError(
        `Unsupported KMS envelope version ${parsed.version}`,
        'KMS_ENVELOPE_UNSUPPORTED_VERSION',
      );
    }

    const provider = this.resolveProvider(parsed.providerId, parsed.keyId);
    const dataKey = await provider.unwrapDataKey(parsed.wrappedKey, context);

    try {
      if (dataKey.length !== KMS_DATA_KEY_BYTES) {
        throw new KmsEnvelopeError(
          'Unwrapped data key has an unexpected length',
          'KMS_ENVELOPE_DECRYPT_FAILED',
        );
      }

      const decipher = crypto.createDecipheriv(
        KMS_ENVELOPE_ALGORITHM,
        dataKey,
        parsed.iv,
      );
      decipher.setAuthTag(parsed.authTag);
      const plaintext = Buffer.concat([
        decipher.update(parsed.ciphertext),
        decipher.final(),
      ]);
      return plaintext.toString('utf8');
    } catch (error) {
      if (error instanceof KmsEnvelopeError) throw error;
      throw new KmsEnvelopeError(
        'Encrypted secret failed authentication',
        'KMS_ENVELOPE_DECRYPT_FAILED',
      );
    } finally {
      dataKey.fill(0);
    }
  }

  /** True when the envelope was produced by a stale provider/master key. */
  needsRotation(envelope: string): boolean {
    const parsed = parseEnvelope(envelope);
    return (
      parsed.version !== KMS_ENVELOPE_VERSION ||
      parsed.providerId !== this.provider.providerId ||
      parsed.keyId !== this.provider.keyId
    );
  }

  /**
   * Re-wraps an old envelope under the current master key. The plaintext only
   * ever exists in memory for the duration of the call, so callers can run
   * this over every stored row during a rotation without exposing secrets.
   */
  async rotateEnvelope(
    envelope: string,
    context?: Record<string, string>,
  ): Promise<KmsRotationResult> {
    if (!this.needsRotation(envelope)) {
      return { envelope, rotated: false };
    }

    const plaintext = await this.decryptSecret(envelope, context);
    try {
      return {
        envelope: await this.encryptSecret(plaintext, context),
        rotated: true,
      };
    } finally {
      // Strings are immutable; drop the reference as soon as possible.
    }
  }

  private resolveProvider(
    providerId: KmsEnvelopeProviderId,
    keyId: string,
  ): KmsEnvelopeProvider {
    for (const provider of [this.provider, ...this.decryptionProviders]) {
      if (provider.providerId !== providerId) continue;
      const accepts = provider.acceptsKeyId
        ? provider.acceptsKeyId(keyId)
        : provider.keyId === keyId;
      if (accepts) return provider;
    }

    throw new KmsEnvelopeError(
      `No configured KMS provider can decrypt an envelope from ${providerId} (${keyId})`,
      'KMS_ENVELOPE_UNKNOWN_KEY',
    );
  }
}

export interface CreateKmsKeyServiceDeps {
  awsClient?: AwsKmsEnvelopeClientLike;
  vaultClient?: VaultTransitEnvelopeClientLike;
}

function parseOldLocalKeys(raw: string | undefined): Record<number, string> {
  if (!raw) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    const keys: Record<number, string> = {};
    for (const [version, value] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof value === 'string' && value.length > 0) {
        keys[Number(version)] = value;
      }
    }
    return keys;
  } catch {
    return {};
  }
}

/**
 * Builds the process-wide KMS key service from environment configuration.
 *
 * - `KMS_PROVIDER=aws` + `KMS_KEY_ID` uses the injected AWS client.
 * - `KMS_PROVIDER=vault` + `VAULT_KMS_KEY_NAME` uses the injected Vault client.
 * - Anything else (or a requested provider without its client) transparently
 *   falls back to local AES-256-GCM envelope encryption keyed by
 *   `KMS_LOCAL_MASTER_KEY` / `MASTER_ENCRYPTION_KEY`.
 */
export function createKmsKeyServiceFromEnv(
  env: NodeJS.ProcessEnv = process.env,
  deps: CreateKmsKeyServiceDeps = {},
): KmsKeyService {
  const requested = env.KMS_PROVIDER?.toLowerCase();

  if (requested === 'aws' && deps.awsClient && env.KMS_KEY_ID) {
    return new KmsKeyService({
      provider: new AwsKmsEnvelopeProvider(deps.awsClient, env.KMS_KEY_ID),
    });
  }

  if (requested === 'vault' && deps.vaultClient && env.VAULT_KMS_KEY_NAME) {
    return new KmsKeyService({
      provider: new VaultTransitEnvelopeProvider(
        deps.vaultClient,
        env.VAULT_KMS_KEY_NAME,
      ),
    });
  }

  const masterKey = env.KMS_LOCAL_MASTER_KEY ?? env.MASTER_ENCRYPTION_KEY;
  if (!masterKey) {
    throw new KmsConfigurationError(
      'KMS is not configured: set KMS_KEY_ID (AWS), VAULT_KMS_KEY_NAME (Vault), or MASTER_ENCRYPTION_KEY for the local fallback',
    );
  }

  const version = Number(env.MASTER_ENCRYPTION_KEY_VERSION ?? '1');
  return new KmsKeyService({
    provider: new LocalEnvelopeProvider({
      masterKey,
      version: Number.isInteger(version) && version > 0 ? version : 1,
      oldKeys: parseOldLocalKeys(env.MASTER_ENCRYPTION_OLD_KEYS),
    }),
  });
}
