/**
 * Unit tests for KMS envelope encryption of webhook signing secrets (#927).
 * A fake AWS KMS client keeps the suite network-free while still exercising
 * the GenerateDataKey -> AES-GCM -> Decrypt round trip and key rotation.
 */
import crypto from 'crypto';
import { describe, it, expect, vi } from 'vitest';
import {
  AwsKmsEnvelopeProvider,
  KmsEnvelopeError,
  KmsKeyService,
  LocalEnvelopeProvider,
  VaultTransitEnvelopeProvider,
  createKmsKeyServiceFromEnv,
  isKmsEnvelope,
  KMS_ENVELOPE_PREFIX,
} from '../kms';

function createFakeAwsKms() {
  const wrappedKeys = new Map<string, Buffer>();
  const generateCalls: Array<Record<string, unknown>> = [];
  const decryptCalls: Array<Record<string, unknown>> = [];
  let sequence = 0;

  return {
    generateCalls,
    decryptCalls,
    async generateDataKey(params: Record<string, unknown>) {
      generateCalls.push(params);
      const plaintext = crypto.randomBytes(32);
      const token = `wrapped-data-key-${sequence++}`;
      wrappedKeys.set(token, plaintext);
      return {
        Plaintext: new Uint8Array(plaintext),
        CiphertextBlob: new Uint8Array(Buffer.from(token)),
      };
    },
    async decrypt(params: Record<string, unknown>) {
      decryptCalls.push(params);
      const token = Buffer.from(params.CiphertextBlob as Uint8Array).toString('utf8');
      const plaintext = wrappedKeys.get(token);
      return plaintext ? { Plaintext: new Uint8Array(plaintext) } : {};
    },
  };
}

// Generated at runtime so no literal secret-like value lives in the repo.
const SECRET = crypto.randomBytes(24).toString('hex');

describe('KmsKeyService envelope round trip (#927)', () => {
  it('encrypts and decrypts through a mocked AWS KMS master key', async () => {
    const aws = createFakeAwsKms();
    const service = new KmsKeyService({
      provider: new AwsKmsEnvelopeProvider(aws, 'arn:aws:kms:us-east-1:123:key/webhooks'),
    });

    const envelope = await service.encryptSecret(SECRET, { tenant: 'acme' });

    expect(envelope.split(':')).toHaveLength(8);
    expect(envelope.startsWith(`${KMS_ENVELOPE_PREFIX}:v1:aws:`)).toBe(true);
    expect(envelope).not.toContain(SECRET);
    expect(aws.generateCalls[0]).toMatchObject({
      KeyId: 'arn:aws:kms:us-east-1:123:key/webhooks',
      KeySpec: 'AES_256',
      EncryptionContext: { tenant: 'acme' },
    });

    await expect(service.decryptSecret(envelope, { tenant: 'acme' })).resolves.toBe(SECRET);
    expect(isKmsEnvelope(envelope)).toBe(true);
  });

  it('never persists the plaintext data key', async () => {
    const aws = createFakeAwsKms();
    const service = new KmsKeyService({
      provider: new AwsKmsEnvelopeProvider(aws, 'alias/webhooks'),
    });

    const envelope = await service.encryptSecret(SECRET);
    const wrapped = envelope.split(':')[4];

    // The stored wrapped key is the opaque KMS ciphertext blob, not raw bytes.
    const kmsBlob = Buffer.from(wrapped, 'base64url').toString('utf8');
    expect(Buffer.from(kmsBlob, 'base64').toString('utf8')).toMatch(
      /^wrapped-data-key-/,
    );
  });

  it('rejects a tampered ciphertext', async () => {
    const aws = createFakeAwsKms();
    const service = new KmsKeyService({
      provider: new AwsKmsEnvelopeProvider(aws, 'alias/webhooks'),
    });

    const parts = (await service.encryptSecret(SECRET)).split(':');
    const ciphertext = Buffer.from(parts[7], 'base64url');
    ciphertext[0] ^= 0xff;
    parts[7] = ciphertext.toString('base64url');

    await expect(service.decryptSecret(parts.join(':'))).rejects.toThrow(
      /failed authentication/i,
    );
  });

  it('rejects malformed envelopes without leaking details', async () => {
    const service = new KmsKeyService({
      provider: new LocalEnvelopeProvider({ masterKey: 'local-master' }),
    });

    await expect(service.decryptSecret('not-an-envelope')).rejects.toBeInstanceOf(
      KmsEnvelopeError,
    );
    await expect(service.decryptSecret('kms:v1:aws:a:b:c:d')).rejects.toThrow(
      /invalid kms envelope format/i,
    );
    expect(isKmsEnvelope('kms:v1:aws:a:b:c:d')).toBe(false);
  });

  it('re-encrypts automatically when the master key rotates', async () => {
    const aws = createFakeAwsKms();
    const oldProvider = new AwsKmsEnvelopeProvider(aws, 'alias/webhooks-v1');
    const oldService = new KmsKeyService({ provider: oldProvider });
    const oldEnvelope = await oldService.encryptSecret(SECRET);

    const newProvider = new AwsKmsEnvelopeProvider(aws, 'alias/webhooks-v2');
    const rotatedService = new KmsKeyService({
      provider: newProvider,
      decryptionProviders: [oldProvider],
    });

    expect(rotatedService.needsRotation(oldEnvelope)).toBe(true);
    // The old envelope stays readable during the rotation window.
    await expect(rotatedService.decryptSecret(oldEnvelope)).resolves.toBe(SECRET);

    const rotation = await rotatedService.rotateEnvelope(oldEnvelope);
    expect(rotation.rotated).toBe(true);
    expect(rotation.envelope).not.toBe(oldEnvelope);
    expect(rotatedService.needsRotation(rotation.envelope)).toBe(false);
    await expect(rotatedService.decryptSecret(rotation.envelope)).resolves.toBe(SECRET);

    // A second pass is a no-op, so rotation jobs are idempotent.
    await expect(rotatedService.rotateEnvelope(rotation.envelope)).resolves.toEqual({
      envelope: rotation.envelope,
      rotated: false,
    });
  });

  it('fails closed when the old master key is not configured', async () => {
    const aws = createFakeAwsKms();
    const oldEnvelope = await new KmsKeyService({
      provider: new AwsKmsEnvelopeProvider(aws, 'alias/webhooks-v1'),
    }).encryptSecret(SECRET);

    const unknownService = new KmsKeyService({
      provider: new AwsKmsEnvelopeProvider(aws, 'alias/webhooks-v3'),
    });

    await expect(unknownService.decryptSecret(oldEnvelope)).rejects.toThrow(
      /no configured kms provider/i,
    );
  });
});

describe('Local envelope provider fallback (#927)', () => {
  it('round-trips with a local master key', async () => {
    const service = new KmsKeyService({
      provider: new LocalEnvelopeProvider({ masterKey: 'local-master-key' }),
    });

    const envelope = await service.encryptSecret(SECRET);
    expect(envelope).toContain(':local:');
    await expect(service.decryptSecret(envelope)).resolves.toBe(SECRET);
  });

  it('decrypts old versions from its keyring and rotates them', async () => {
    const v1 = new KmsKeyService({
      provider: new LocalEnvelopeProvider({ masterKey: 'master-v1', version: 1 }),
    });
    const oldEnvelope = await v1.encryptSecret(SECRET);

    const v2Provider = new LocalEnvelopeProvider({
      masterKey: 'master-v2',
      version: 2,
      oldKeys: { 1: 'master-v1' },
    });
    const v2 = new KmsKeyService({ provider: v2Provider });

    expect(v2.needsRotation(oldEnvelope)).toBe(true);
    await expect(v2.decryptSecret(oldEnvelope)).resolves.toBe(SECRET);

    const rotated = await v2.rotateEnvelope(oldEnvelope);
    expect(rotated.envelope).toContain(':' + Buffer.from('local/v2').toString('base64url') + ':');
    await expect(v2.decryptSecret(rotated.envelope)).resolves.toBe(SECRET);
  });

  it('does not decrypt with the wrong local master key', async () => {
    const envelope = await new KmsKeyService({
      provider: new LocalEnvelopeProvider({ masterKey: 'master-a' }),
    }).encryptSecret(SECRET);

    const other = new KmsKeyService({
      provider: new LocalEnvelopeProvider({ masterKey: 'master-b' }),
    });

    await expect(other.decryptSecret(envelope)).rejects.toThrow(/could not be unwrapped/i);
  });

  it('requires a master key', () => {
    expect(() => new LocalEnvelopeProvider({ masterKey: '' })).toThrow(
      /requires a master key/i,
    );
  });
});

describe('Vault Transit adapter (#927)', () => {
  it('wraps and unwraps data keys through the transit engine', async () => {
    const vault = {
      generateDataKey: vi.fn(async () => ({
        plaintext: Buffer.from('k'.repeat(32)).toString('base64'),
        ciphertext: 'vault:v1:wrapped',
      })),
      decrypt: vi.fn(async () => ({
        plaintext: Buffer.from('k'.repeat(32)).toString('base64'),
      })),
    };

    const service = new KmsKeyService({
      provider: new VaultTransitEnvelopeProvider(vault, 'webhook-secrets'),
    });

    const envelope = await service.encryptSecret(SECRET);
    expect(vault.generateDataKey).toHaveBeenCalledWith('webhook-secrets', undefined);
    expect(envelope).toContain(':vault:');
    await expect(service.decryptSecret(envelope)).resolves.toBe(SECRET);
    expect(vault.decrypt).toHaveBeenCalledWith(
      'webhook-secrets',
      'vault:v1:wrapped',
      undefined,
    );
  });
});

describe('createKmsKeyServiceFromEnv (#927)', () => {
  it('uses AWS when a client and key id are configured', async () => {
    const aws = createFakeAwsKms();
    const service = createKmsKeyServiceFromEnv(
      {
        KMS_PROVIDER: 'aws',
        KMS_KEY_ID: 'alias/prod-webhooks',
      } as NodeJS.ProcessEnv,
      { awsClient: aws },
    );

    expect(service.providerId).toBe('aws');
    const envelope = await service.encryptSecret(SECRET);
    await expect(service.decryptSecret(envelope)).resolves.toBe(SECRET);
  });

  it('falls back to local encryption when KMS credentials are missing', async () => {
    const service = createKmsKeyServiceFromEnv({
      KMS_PROVIDER: 'aws',
      MASTER_ENCRYPTION_KEY: 'fallback-master',
    } as NodeJS.ProcessEnv);

    expect(service.providerId).toBe('local');
    const envelope = await service.encryptSecret(SECRET);
    await expect(service.decryptSecret(envelope)).resolves.toBe(SECRET);
  });

  it('reads the local keyring from the existing encryption env vars', async () => {
    const oldService = createKmsKeyServiceFromEnv({
      MASTER_ENCRYPTION_KEY: 'old-master',
      MASTER_ENCRYPTION_KEY_VERSION: '1',
    } as NodeJS.ProcessEnv);
    const envelope = await oldService.encryptSecret(SECRET);

    const rotated = createKmsKeyServiceFromEnv({
      MASTER_ENCRYPTION_KEY: 'new-master',
      MASTER_ENCRYPTION_KEY_VERSION: '2',
      MASTER_ENCRYPTION_OLD_KEYS: JSON.stringify({ 1: 'old-master' }),
    } as NodeJS.ProcessEnv);

    await expect(rotated.decryptSecret(envelope)).resolves.toBe(SECRET);
    expect(rotated.needsRotation(envelope)).toBe(true);
  });

  it('throws a configuration error when no key material exists at all', () => {
    expect(() => createKmsKeyServiceFromEnv({} as NodeJS.ProcessEnv)).toThrow(
      /kms is not configured/i,
    );
  });
});
