/**
 * End-to-end tests for encrypted webhook delivery (#929): encrypt in the API,
 * decrypt with the recipient private key, and verify both Stellar-native and
 * secp256k1 key handling.
 */
import crypto from 'crypto';
import nacl from 'tweetnacl';
import { Keypair } from 'stellar-sdk';
import { describe, it, expect } from 'vitest';
import {
  ECIES_ALGORITHM,
  EciesError,
  EciesPayloadEncryptor,
  STELLAR_ALERTS_ENCRYPTION_HEADER,
  STELLAR_ALERTS_EPHEMERAL_KEY_HEADER,
  decryptEciesPayload,
  encryptEciesPayload,
  isEciesEnvelope,
  resolveEciesRecipientKey,
} from '../ecies';

function x25519KeyPair() {
  const keyPair = nacl.box.keyPair();
  return {
    publicKey: Buffer.from(keyPair.publicKey).toString('base64'),
    privateKey: Buffer.from(keyPair.secretKey).toString('base64'),
  };
}

const ALERT_PAYLOAD = {
  event: 'payment.received',
  data: {
    txHash: 'a'.repeat(64),
    amount: '1250.0000000',
    asset: 'XLM',
    fromAddress: 'GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUV',
  },
};

describe('ECIES x25519 delivery (#929)', () => {
  it('round-trips a JSON alert with a raw X25519 key pair', () => {
    const recipient = x25519KeyPair();
    const plaintext = JSON.stringify(ALERT_PAYLOAD);

    const sealed = encryptEciesPayload(plaintext, recipient.publicKey);

    expect(isEciesEnvelope(sealed.envelope)).toBe(true);
    expect(sealed.envelope.curve).toBe('x25519');
    expect(sealed.envelope.alg).toBe(ECIES_ALGORITHM);
    expect(sealed.envelope.ct).not.toContain('txHash');
    expect(JSON.parse(sealed.body)).toEqual(sealed.envelope);

    expect(sealed.headers[STELLAR_ALERTS_EPHEMERAL_KEY_HEADER]).toBe(
      sealed.envelope.epk,
    );
    expect(sealed.headers[STELLAR_ALERTS_ENCRYPTION_HEADER]).toBe(
      'v1;curve=x25519;alg=AES-256-GCM',
    );

    expect(decryptEciesPayload(sealed.envelope, recipient.privateKey)).toBe(
      plaintext,
    );
  });

  it('uses a fresh ephemeral key for every delivery', () => {
    const recipient = x25519KeyPair();
    const first = encryptEciesPayload('{"n":1}', recipient.publicKey);
    const second = encryptEciesPayload('{"n":1}', recipient.publicKey);

    expect(first.envelope.epk).not.toBe(second.envelope.epk);
    expect(first.body).not.toBe(second.body);
    expect(decryptEciesPayload(first.body, recipient.privateKey)).toBe('{"n":1}');
  });

  it('rejects decryption with the wrong private key', () => {
    const recipient = x25519KeyPair();
    const attacker = x25519KeyPair();
    const sealed = encryptEciesPayload('{"secret":true}', recipient.publicKey);

    expect(() => decryptEciesPayload(sealed.body, attacker.privateKey)).toThrow(
      /failed authentication/i,
    );
  });

  it('rejects a tampered ciphertext or auth tag', () => {
    const recipient = x25519KeyPair();
    const sealed = encryptEciesPayload('{"amount":"10"}', recipient.publicKey);

    const tamperedCiphertext = {
      ...sealed.envelope,
      ct: Buffer.from(
        Buffer.from(sealed.envelope.ct, 'base64').fill(0, 0, 1),
      ).toString('base64'),
    };
    expect(() =>
      decryptEciesPayload(tamperedCiphertext, recipient.privateKey),
    ).toThrow(/failed authentication/i);

    const tamperedTag = {
      ...sealed.envelope,
      tag: Buffer.alloc(16).toString('base64'),
    };
    expect(() => decryptEciesPayload(tamperedTag, recipient.privateKey)).toThrow(
      /failed authentication/i,
    );
  });

  it('rejects malformed envelopes and keys', () => {
    expect(() => decryptEciesPayload('not-json', x25519KeyPair().privateKey)).toThrow(
      EciesError,
    );
    expect(() =>
      encryptEciesPayload('{}', 'not-a-key'),
    ).toThrow(/unsupported recipient key/i);
    expect(() => decryptEciesPayload(
      {
        v: 1,
        alg: 'AES-256-GCM',
        curve: 'x25519',
        epk: Buffer.alloc(7).toString('base64'),
        iv: Buffer.alloc(12).toString('base64'),
        ct: '',
        tag: Buffer.alloc(16).toString('base64'),
      },
      x25519KeyPair().privateKey,
    )).toThrow(/invalid ecies envelope/i);
  });
});

describe('ECIES with Stellar account keys (#929)', () => {
  it('encrypts to a G... account key and decrypts with the S... seed', () => {
    const keypair = Keypair.random();
    const sealed = encryptEciesPayload(
      JSON.stringify(ALERT_PAYLOAD),
      keypair.publicKey(),
    );

    expect(sealed.envelope.curve).toBe('x25519');
    expect(decryptEciesPayload(sealed.body, keypair.secret())).toEqual(
      JSON.stringify(ALERT_PAYLOAD),
    );
  });

  it('accepts raw ed25519 public/secret keys', () => {
    const keypair = Keypair.random();
    const publicKey = keypair.rawPublicKey();
    const secretKey = keypair.rawSecretKey();

    const sealed = encryptEciesPayload(
      '{"event":"soroban.contract_event"}',
      `ed25519:${Buffer.from(publicKey).toString('hex')}`,
    );

    expect(
      decryptEciesPayload(sealed.body, `ed25519:${Buffer.from(secretKey).toString('hex')}`),
    ).toBe('{"event":"soroban.contract_event"}');
  });

  it('normalizes a Stellar G... key to the same X25519 key as its raw form', () => {
    const keypair = Keypair.random();
    const fromStellar = resolveEciesRecipientKey(keypair.publicKey());
    const fromRaw = resolveEciesRecipientKey(
      `ed25519:${Buffer.from(keypair.rawPublicKey()).toString('hex')}`,
    );

    expect(fromStellar.curve).toBe('x25519');
    expect(fromStellar.publicKey.equals(fromRaw.publicKey)).toBe(true);
  });
});

describe('ECIES secp256k1 delivery (#929)', () => {
  it('round-trips with an uncompressed secp256k1 key', () => {
    const recipient = crypto.createECDH('secp256k1');
    recipient.generateKeys();

    const sealed = encryptEciesPayload(
      '{"asset":"USDC"}',
      `secp256k1:${recipient.getPublicKey(undefined, 'uncompressed').toString('base64')}`,
    );

    expect(sealed.envelope.curve).toBe('secp256k1');
    expect(decryptEciesPayload(sealed.body, `secp256k1:${recipient.getPrivateKey().toString('hex')}`)).toBe(
      '{"asset":"USDC"}',
    );
  });

  it('accepts a compressed SEC1 public key', () => {
    const recipient = crypto.createECDH('secp256k1');
    recipient.generateKeys();
    const compressed = crypto.ECDH.convertKey(
      recipient.getPublicKey(undefined, 'uncompressed'),
      'secp256k1',
      undefined,
      undefined,
      'compressed',
    ) as Buffer;

    const sealed = encryptEciesPayload('{"ok":true}', compressed.toString('base64'));
    expect(sealed.envelope.curve).toBe('secp256k1');
    expect(
      decryptEciesPayload(sealed.body, recipient.getPrivateKey().toString('base64')),
    ).toBe('{"ok":true}');
  });
});

describe('EciesPayloadEncryptor integration surface (#929)', () => {
  it('encryptJson returns a transport-ready body and headers', () => {
    const recipient = x25519KeyPair();
    const encryptor = new EciesPayloadEncryptor();

    const sealed = encryptor.encryptJson(ALERT_PAYLOAD, recipient.publicKey);

    expect(JSON.parse(sealed.body)).toMatchObject({
      v: 1,
      alg: 'AES-256-GCM',
      curve: 'x25519',
    });
    expect(sealed.headers['Content-Type']).toBe('application/json');
    expect(
      JSON.parse(encryptor.decrypt(sealed.body, recipient.privateKey)),
    ).toEqual(ALERT_PAYLOAD);
  });

  it('supports per-encryptor default options', () => {
    const recipient = crypto.createECDH('secp256k1');
    recipient.generateKeys();
    const encryptor = new EciesPayloadEncryptor({ curve: 'secp256k1' });

    const sealed = encryptor.encryptJson(
      { curve: 'secp256k1' },
      recipient.getPublicKey(undefined, 'uncompressed').toString('base64'),
    );

    expect(sealed.envelope.curve).toBe('secp256k1');
  });
});
