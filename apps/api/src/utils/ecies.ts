import crypto from 'crypto';
import nacl from 'tweetnacl';
import { Keypair } from 'stellar-sdk';
import { isValidEd25519PublicKey } from '@stellar-alerts/shared';
// ed2curve has no published type declarations; see src/types/ed2curve.d.ts.
import ed2curve from 'ed2curve';

/**
 * End-to-end encrypted webhook payload delivery (#929).
 *
 * Standard TLS terminates at the first load balancer or CDN in front of the
 * receiver, so intermediaries can read payment amounts and counterparty
 * identities. This module implements ECIES: the API encrypts the exact bytes
 * it is about to POST to the subscriber's public key, and only the holder of
 * the matching private key can open it.
 *
 * Scheme (`stellar-alerts-ecies-v1`):
 *
 *   1. A fresh ephemeral key pair is generated per delivery.
 *   2. `shared = ECDH(ephemeral_private, recipient_public)`.
 *   3. `key = HKDF-SHA256(ikm=shared, salt=ephemeral_public,
 *                          info="stellar-alerts-ecies-v1:<curve>")`.
 *   4. The JSON body is encrypted with AES-256-GCM, using
 *      `"stellar-alerts-ecies-v1:<curve>"` as additional authenticated data.
 *   5. The ephemeral public key travels in `Stellar-Alerts-Ephemeral-Key`;
 *      the nonce, tag and ciphertext travel in a JSON envelope body.
 *
 * Supported recipient keys:
 *   - `x25519`  — a raw 32-byte X25519 key (hex/base64), or a Stellar `G...`
 *                 account key / `ed25519:` raw public key converted with the
 *                 standard Ed25519→Curve25519 birational map. Stellar `S...`
 *                 secret seeds are accepted by {@link EciesPayloadEncryptor.decrypt}.
 *   - `secp256k1` — a compressed or uncompressed SEC1 public key
 *                 (hex/base64, optionally prefixed `secp256k1:`).
 */

export const ECIES_VERSION = 1;
export const ECIES_ALGORITHM = 'AES-256-GCM' as const;
export const ECIES_HKDF_INFO_PREFIX = 'stellar-alerts-ecies-v1';
export const ECIES_IV_BYTES = 12;
export const ECIES_KEY_BYTES = 32;
export const ECIES_GCM_TAG_BYTES = 16;

export const STELLAR_ALERTS_EPHEMERAL_KEY_HEADER = 'Stellar-Alerts-Ephemeral-Key';
export const STELLAR_ALERTS_ENCRYPTION_HEADER = 'Stellar-Alerts-Encryption';

export type EciesCurve = 'x25519' | 'secp256k1';

export interface EciesEncryptedEnvelope {
  v: typeof ECIES_VERSION;
  alg: typeof ECIES_ALGORITHM;
  curve: EciesCurve;
  /** Base64 ephemeral public key. Mirrored in the Ephemeral-Key header. */
  epk: string;
  /** Base64 12-byte AES-GCM nonce. */
  iv: string;
  /** Base64 AES-256-GCM ciphertext. */
  ct: string;
  /** Base64 16-byte AES-GCM authentication tag. */
  tag: string;
}

export interface EncryptedWebhookPayload {
  /** Serialized envelope — the exact webhook request body. */
  body: string;
  envelope: EciesEncryptedEnvelope;
  headers: Record<string, string>;
}

export interface EciesEncryptOptions {
  curve?: EciesCurve;
}

export class EciesError extends Error {
  readonly code: string;

  constructor(message: string, code = 'ECIES_ERROR') {
    super(message);
    this.name = 'EciesError';
    this.code = code;
  }
}

function infoForCurve(curve: EciesCurve): Buffer {
  return Buffer.from(`${ECIES_HKDF_INFO_PREFIX}:${curve}`, 'utf8');
}

function aadForCurve(curve: EciesCurve): Buffer {
  return infoForCurve(curve);
}

function decodeMaybeHexOrBase64(value: string): Buffer | null {
  const trimmed = value.trim();
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
    return Buffer.from(trimmed, 'hex');
  }
  try {
    const decoded = Buffer.from(trimmed, 'base64');
    if (decoded.length > 0 && decoded.toString('base64').replace(/=+$/, '') === trimmed.replace(/=+$/, '')) {
      return decoded;
    }
  } catch {
    // fall through
  }
  return null;
}

function ed25519PublicKeyToX25519(rawEd25519: Uint8Array): Buffer {
  const converted = ed2curve.convertPublicKey(Buffer.from(rawEd25519));
  if (!converted) {
    throw new EciesError('Ed25519 public key could not be converted to X25519', 'ECIES_INVALID_RECIPIENT_KEY');
  }
  return Buffer.from(converted);
}

function ed25519SecretKeyToX25519(rawEd25519Secret: Uint8Array): Buffer {
  const converted = ed2curve.convertSecretKey(Buffer.from(rawEd25519Secret));
  if (!converted) {
    throw new EciesError('Ed25519 secret key could not be converted to X25519', 'ECIES_INVALID_RECIPIENT_KEY');
  }
  return Buffer.from(converted);
}

/** Normalizes any supported recipient public key into a curve + raw bytes. */
export function resolveEciesRecipientKey(
  recipientPublicKey: string,
  options: EciesEncryptOptions = {},
): { curve: EciesCurve; publicKey: Buffer } {
  if (typeof recipientPublicKey !== 'string' || recipientPublicKey.trim().length === 0) {
    throw new EciesError('Recipient public key is required', 'ECIES_INVALID_RECIPIENT_KEY');
  }

  const value = recipientPublicKey.trim();
  const explicitCurve = options.curve;

  if (value.startsWith('secp256k1:') || explicitCurve === 'secp256k1') {
    const raw = value.startsWith('secp256k1:') ? value.slice('secp256k1:'.length) : value;
    const decoded = decodeMaybeHexOrBase64(raw);
    if (!decoded || (decoded.length !== 33 && decoded.length !== 65)) {
      throw new EciesError(
        'secp256k1 recipient key must be a compressed (33-byte) or uncompressed (65-byte) SEC1 key',
        'ECIES_INVALID_RECIPIENT_KEY',
      );
    }
    const uncompressed = crypto.ECDH.convertKey(
      decoded,
      'secp256k1',
      undefined,
      undefined,
      'uncompressed',
    ) as Buffer;
    return { curve: 'secp256k1', publicKey: Buffer.from(uncompressed) };
  }

  if (value.startsWith('x25519:')) {
    const decoded = decodeMaybeHexOrBase64(value.slice('x25519:'.length));
    if (!decoded || decoded.length !== ECIES_KEY_BYTES) {
      throw new EciesError('X25519 recipient key must be 32 bytes', 'ECIES_INVALID_RECIPIENT_KEY');
    }
    return { curve: 'x25519', publicKey: decoded };
  }

  if (value.startsWith('ed25519:')) {
    const decoded = decodeMaybeHexOrBase64(value.slice('ed25519:'.length));
    if (!decoded || decoded.length !== ECIES_KEY_BYTES) {
      throw new EciesError('Ed25519 recipient key must be 32 bytes', 'ECIES_INVALID_RECIPIENT_KEY');
    }
    return { curve: 'x25519', publicKey: ed25519PublicKeyToX25519(decoded) };
  }

  if (isValidEd25519PublicKey(value)) {
    const raw = Keypair.fromPublicKey(value).rawPublicKey();
    return { curve: 'x25519', publicKey: ed25519PublicKeyToX25519(raw) };
  }

  const decoded = decodeMaybeHexOrBase64(value);
  if (decoded && decoded.length === ECIES_KEY_BYTES) {
    return { curve: 'x25519', publicKey: decoded };
  }
  if (decoded && (decoded.length === 33 || decoded.length === 65)) {
    const uncompressed = crypto.ECDH.convertKey(
      decoded,
      'secp256k1',
      undefined,
      undefined,
      'uncompressed',
    ) as Buffer;
    return { curve: 'secp256k1', publicKey: Buffer.from(uncompressed) };
  }

  throw new EciesError(
    'Unsupported recipient key: use a Stellar G... key, a raw 32-byte X25519 key, or a secp256k1 key',
    'ECIES_INVALID_RECIPIENT_KEY',
  );
}

function resolveDecryptionPrivateKey(
  recipientPrivateKey: string,
  curve: EciesCurve,
): Buffer {
  if (typeof recipientPrivateKey !== 'string' || recipientPrivateKey.trim().length === 0) {
    throw new EciesError('Recipient private key is required', 'ECIES_INVALID_RECIPIENT_KEY');
  }
  const value = recipientPrivateKey.trim();

  if (curve === 'secp256k1') {
    const raw = value.startsWith('secp256k1:') ? value.slice('secp256k1:'.length) : value;
    const decoded = decodeMaybeHexOrBase64(raw);
    if (!decoded || decoded.length !== ECIES_KEY_BYTES) {
      throw new EciesError('secp256k1 private key must be 32 bytes', 'ECIES_INVALID_RECIPIENT_KEY');
    }
    return decoded;
  }

  if (value.startsWith('x25519:')) {
    const decoded = decodeMaybeHexOrBase64(value.slice('x25519:'.length));
    if (!decoded || decoded.length !== ECIES_KEY_BYTES) {
      throw new EciesError('X25519 private key must be 32 bytes', 'ECIES_INVALID_RECIPIENT_KEY');
    }
    return decoded;
  }

  if (value.startsWith('ed25519:')) {
    const decoded = decodeMaybeHexOrBase64(value.slice('ed25519:'.length));
    if (!decoded || decoded.length !== ECIES_KEY_BYTES) {
      throw new EciesError('Ed25519 secret key must be 32 bytes', 'ECIES_INVALID_RECIPIENT_KEY');
    }
    return ed25519SecretKeyToX25519(decoded);
  }

  // Stellar secret seed (S...): convert the Ed25519 seed to its X25519 form so
  // subscribers can decrypt with the same key pair that owns their account.
  if (/^S[A-Z2-7]{55}$/.test(value)) {
    try {
      const raw = Keypair.fromSecret(value).rawSecretKey();
      return ed25519SecretKeyToX25519(raw);
    } catch {
      throw new EciesError('Invalid Stellar secret key', 'ECIES_INVALID_RECIPIENT_KEY');
    }
  }

  const decoded = decodeMaybeHexOrBase64(value);
  if (decoded && decoded.length === ECIES_KEY_BYTES) {
    return decoded;
  }

  throw new EciesError(
    'Unsupported private key: use an S... Stellar seed, x25519:/ed25519: 32-byte key, or a hex/base64 private key',
    'ECIES_INVALID_RECIPIENT_KEY',
  );
}

function computeSharedSecret(
  curve: EciesCurve,
  privateKey: Buffer,
  peerPublicKey: Buffer,
): Buffer {
  try {
    if (curve === 'x25519') {
      if (privateKey.length !== ECIES_KEY_BYTES || peerPublicKey.length !== ECIES_KEY_BYTES) {
        throw new Error('invalid X25519 key length');
      }
      return Buffer.from(
        nacl.scalarMult(new Uint8Array(privateKey), new Uint8Array(peerPublicKey)),
      );
    }

    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(privateKey);
    return Buffer.from(ecdh.computeSecret(peerPublicKey));
  } catch {
    throw new EciesError(
      'ECDH key agreement failed; the key pair does not match the envelope',
      'ECIES_KEY_AGREEMENT_FAILED',
    );
  }
}

function generateEphemeralKeyPair(curve: EciesCurve): { privateKey: Buffer; publicKey: Buffer } {
  if (curve === 'x25519') {
    const keyPair = nacl.box.keyPair();
    return {
      privateKey: Buffer.from(keyPair.secretKey),
      publicKey: Buffer.from(keyPair.publicKey),
    };
  }

  const ecdh = crypto.createECDH('secp256k1');
  ecdh.generateKeys();
  return {
    privateKey: Buffer.from(ecdh.getPrivateKey()),
    publicKey: Buffer.from(ecdh.getPublicKey(undefined, 'uncompressed')),
  };
}

function deriveAesKey(sharedSecret: Buffer, ephemeralPublicKey: Buffer, curve: EciesCurve): Buffer {
  return Buffer.from(
    crypto.hkdfSync(
      'sha256',
      sharedSecret,
      ephemeralPublicKey,
      infoForCurve(curve),
      ECIES_KEY_BYTES,
    ),
  );
}

export function isEciesEnvelope(value: unknown): value is EciesEncryptedEnvelope {
  if (!value || typeof value !== 'object') return false;
  const envelope = value as Partial<EciesEncryptedEnvelope>;
  return (
    envelope.v === ECIES_VERSION &&
    envelope.alg === ECIES_ALGORITHM &&
    (envelope.curve === 'x25519' || envelope.curve === 'secp256k1') &&
    typeof envelope.epk === 'string' &&
    typeof envelope.iv === 'string' &&
    typeof envelope.ct === 'string' &&
    typeof envelope.tag === 'string'
  );
}

function parseEnvelope(input: EciesEncryptedEnvelope | string): EciesEncryptedEnvelope {
  let envelope: unknown = input;
  if (typeof input === 'string') {
    try {
      envelope = JSON.parse(input);
    } catch {
      throw new EciesError('Invalid ECIES envelope', 'ECIES_INVALID_ENVELOPE');
    }
  }
  if (!isEciesEnvelope(envelope)) {
    throw new EciesError('Invalid ECIES envelope', 'ECIES_INVALID_ENVELOPE');
  }

  const iv = Buffer.from(envelope.iv, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  const ephemeralPublicKey = Buffer.from(envelope.epk, 'base64');
  const expectedEphemeralLength = envelope.curve === 'x25519' ? ECIES_KEY_BYTES : 65;
  if (
    iv.length !== ECIES_IV_BYTES ||
    tag.length !== ECIES_GCM_TAG_BYTES ||
    ephemeralPublicKey.length !== expectedEphemeralLength
  ) {
    throw new EciesError('Invalid ECIES envelope parameters', 'ECIES_INVALID_ENVELOPE');
  }
  return envelope;
}

/**
 * Encrypts a JSON webhook body for a recipient public key.
 *
 * The returned object contains the serialized envelope (use it verbatim as the
 * request body) and the headers that advertise the ephemeral key, so a
 * receiver can decrypt without any out-of-band state.
 */
export function encryptEciesPayload(
  plaintext: string,
  recipientPublicKey: string,
  options: EciesEncryptOptions = {},
): EncryptedWebhookPayload {
  if (typeof plaintext !== 'string') {
    throw new EciesError('Payload must be a string', 'ECIES_INVALID_PAYLOAD');
  }

  const { curve, publicKey } = resolveEciesRecipientKey(recipientPublicKey, options);
  const ephemeral = generateEphemeralKeyPair(curve);
  const sharedSecret = computeSharedSecret(curve, ephemeral.privateKey, publicKey);
  const aesKey = deriveAesKey(sharedSecret, ephemeral.publicKey, curve);

  try {
    const iv = crypto.randomBytes(ECIES_IV_BYTES);
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    cipher.setAAD(aadForCurve(curve));
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);

    const envelope: EciesEncryptedEnvelope = {
      v: ECIES_VERSION,
      alg: ECIES_ALGORITHM,
      curve,
      epk: ephemeral.publicKey.toString('base64'),
      iv: iv.toString('base64'),
      ct: ciphertext.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
    };

    return {
      body: JSON.stringify(envelope),
      envelope,
      headers: {
        'Content-Type': 'application/json',
        [STELLAR_ALERTS_EPHEMERAL_KEY_HEADER]: envelope.epk,
        [STELLAR_ALERTS_ENCRYPTION_HEADER]: `v${ECIES_VERSION};curve=${curve};alg=${ECIES_ALGORITHM}`,
      },
    };
  } finally {
    sharedSecret.fill(0);
    aesKey.fill(0);
    ephemeral.privateKey.fill(0);
  }
}

/** Decrypts an envelope with the recipient private key. */
export function decryptEciesPayload(
  envelopeInput: EciesEncryptedEnvelope | string,
  recipientPrivateKey: string,
): string {
  const envelope = parseEnvelope(envelopeInput);
  const privateKey = resolveDecryptionPrivateKey(recipientPrivateKey, envelope.curve);
  const ephemeralPublicKey = Buffer.from(envelope.epk, 'base64');
  const sharedSecret = computeSharedSecret(envelope.curve, privateKey, ephemeralPublicKey);
  const aesKey = deriveAesKey(sharedSecret, ephemeralPublicKey, envelope.curve);

  try {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      aesKey,
      Buffer.from(envelope.iv, 'base64'),
    );
    decipher.setAAD(aadForCurve(envelope.curve));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));

    return Buffer.concat([
      decipher.update(Buffer.from(envelope.ct, 'base64')),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    throw new EciesError(
      'Encrypted webhook payload failed authentication',
      'ECIES_DECRYPT_FAILED',
    );
  } finally {
    sharedSecret.fill(0);
    aesKey.fill(0);
    privateKey.fill(0);
  }
}

/**
 * Stateful helper used by the dispatcher. Keeping the encryptor as a class
 * leaves room for per-subscriber defaults (curve, key cache) without changing
 * the pure functions above.
 */
export class EciesPayloadEncryptor {
  constructor(private readonly defaults: EciesEncryptOptions = {}) {}

  encrypt(
    plaintext: string,
    recipientPublicKey: string,
    options: EciesEncryptOptions = {},
  ): EncryptedWebhookPayload {
    return encryptEciesPayload(plaintext, recipientPublicKey, {
      ...this.defaults,
      ...options,
    });
  }

  encryptJson(
    payload: unknown,
    recipientPublicKey: string,
    options: EciesEncryptOptions = {},
  ): EncryptedWebhookPayload {
    return this.encrypt(JSON.stringify(payload), recipientPublicKey, options);
  }

  decrypt(envelope: EciesEncryptedEnvelope | string, recipientPrivateKey: string): string {
    return decryptEciesPayload(envelope, recipientPrivateKey);
  }
}
