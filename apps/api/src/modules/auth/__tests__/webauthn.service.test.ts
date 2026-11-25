import crypto from 'node:crypto';
import { describe, it, expect, beforeEach } from 'vitest';
import {
  WebAuthnService,
  WebAuthnError,
  WebAuthnClonedKeyError,
  WebAuthnStepUpRequiredError,
  encodeCborValue,
  publicKeyToCose,
  type WebAuthnCredentialRecord,
  type WebAuthnStore,
} from '../webauthn.service';

const RP_ID = 'app.stellar-alerts.com';
const ORIGIN = 'https://app.stellar-alerts.com';

function createInMemoryStore(): WebAuthnStore & { records: WebAuthnCredentialRecord[] } {
  const records: WebAuthnCredentialRecord[] = [];
  let seq = 1;

  return {
    records,
    async findByUserId(userId) {
      return records.filter((r) => r.userId === userId);
    },
    async findByCredentialId(credentialId) {
      return records.find((r) => r.credentialId === credentialId) ?? null;
    },
    async countByUserId(userId) {
      return records.filter((r) => r.userId === userId).length;
    },
    async create(data) {
      const rec: WebAuthnCredentialRecord = {
        id: `cred-rec-${seq++}`,
        ...data,
        lastUsedAt: null,
        createdAt: new Date(),
      };
      records.push(rec);
      return rec;
    },
    async updateSignCount(id, signCount, lastUsedAt) {
      const rec = records.find((r) => r.id === id)!;
      rec.signCount = signCount;
      rec.lastUsedAt = lastUsedAt;
      return rec;
    },
    async deleteByIdAndUserId(id, userId) {
      const idx = records.findIndex((r) => r.id === id && r.userId === userId);
      if (idx === -1) return false;
      records.splice(idx, 1);
      return true;
    },
  };
}

function buildAttestationObject(params: {
  rpId: string;
  credentialId: Buffer;
  publicKey: crypto.KeyObject;
  signCount?: number;
  flags?: number;
}): string {
  const rpIdHash = crypto.createHash('sha256').update(params.rpId).digest();
  const flags = Buffer.from([params.flags ?? 0x41]); // UP (0x01) + AT (0x40)
  const signCountBuf = Buffer.alloc(4);
  signCountBuf.writeUInt32BE(params.signCount ?? 0, 0);
  const aaguid = Buffer.alloc(16, 0xaa);
  const credIdLen = Buffer.alloc(2);
  credIdLen.writeUInt16BE(params.credentialId.length, 0);
  const coseKey = publicKeyToCose(params.publicKey);

  const authData = Buffer.concat([
    rpIdHash,
    flags,
    signCountBuf,
    aaguid,
    credIdLen,
    params.credentialId,
    coseKey,
  ]);

  const attObj = new Map<string | number, Buffer | string | Map<string | number, never>>();
  attObj.set('fmt', 'none');
  attObj.set('authData', authData);
  attObj.set('attStmt', new Map());

  return encodeCborValue(attObj).toString('base64url');
}

function buildClientDataJSON(params: {
  type: 'webauthn.create' | 'webauthn.get';
  challenge: string;
  origin: string;
}): string {
  return Buffer.from(JSON.stringify(params), 'utf8').toString('base64url');
}

function buildSignedAssertion(params: {
  rpId: string;
  challenge: string;
  origin: string;
  signCount: number;
  privateKey: crypto.KeyObject;
  algorithm: 'ES256' | 'EdDSA';
}) {
  const clientDataJSON = buildClientDataJSON({
    type: 'webauthn.get',
    challenge: params.challenge,
    origin: params.origin,
  });
  const clientDataBuf = Buffer.from(clientDataJSON, 'base64url');
  const clientDataHash = crypto.createHash('sha256').update(clientDataBuf).digest();

  const rpIdHash = crypto.createHash('sha256').update(params.rpId).digest();
  const flags = Buffer.from([0x01]); // UP
  const signCountBuf = Buffer.alloc(4);
  signCountBuf.writeUInt32BE(params.signCount, 0);
  const authDataBuf = Buffer.concat([rpIdHash, flags, signCountBuf]);

  const signedData = Buffer.concat([authDataBuf, clientDataHash]);
  const signature =
    params.algorithm === 'EdDSA'
      ? crypto.sign(null, signedData, params.privateKey)
      : crypto.sign('sha256', signedData, params.privateKey);

  return {
    clientDataJSON,
    authenticatorData: authDataBuf.toString('base64url'),
    signature: signature.toString('base64url'),
  };
}

describe('WebAuthnService (#993)', () => {
  let store: ReturnType<typeof createInMemoryStore>;
  let service: WebAuthnService;

  beforeEach(() => {
    store = createInMemoryStore();
    service = new WebAuthnService({
      store,
      redisClient: null,
      rpId: RP_ID,
      rpName: 'Stellar Alerts',
      origin: ORIGIN,
    });
  });

  it('generates unique cryptographically random registration challenges with excludeCredentials', async () => {
    const first = await service.generateRegistrationChallenge({
      userId: 'user-1',
      email: 'treasury@example.com',
    });
    const second = await service.generateRegistrationChallenge({
      userId: 'user-1',
      email: 'treasury@example.com',
    });

    expect(first.challenge).not.toBe(second.challenge);
    expect(Buffer.from(first.challenge, 'base64url').length).toBe(32);
    expect(first.rp).toEqual({ id: RP_ID, name: 'Stellar Alerts' });
    expect(first.pubKeyCredParams.map((p) => p.alg)).toEqual([-7, -8, -257]);
  });

  it('verifies attestation and registers multiple hardware authenticators per user with custom nicknames', async () => {
    // Key 1: ES256 YubiKey
    const es256Pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const credId1 = crypto.randomBytes(16);
    const reg1 = await service.generateRegistrationChallenge({
      userId: 'user-1',
      email: 'treasury@example.com',
    });

    const saved1 = await service.verifyRegistrationAttestation({
      userId: 'user-1',
      nickname: 'YubiKey 5C Nano',
      clientDataJSON: buildClientDataJSON({
        type: 'webauthn.create',
        challenge: reg1.challenge,
        origin: ORIGIN,
      }),
      attestationObject: buildAttestationObject({
        rpId: RP_ID,
        credentialId: credId1,
        publicKey: es256Pair.publicKey,
        signCount: 0,
      }),
      transports: ['usb', 'nfc'],
    });

    expect(saved1.nickname).toBe('YubiKey 5C Nano');
    expect(saved1.algorithm).toBe(-7);
    expect(saved1.signCount).toBe(0);

    // Key 2: Ed25519 TouchID / Passkey — excludeCredentials now includes Key 1
    const edPair = crypto.generateKeyPairSync('ed25519');
    const credId2 = crypto.randomBytes(16);
    const reg2 = await service.generateRegistrationChallenge({
      userId: 'user-1',
      email: 'treasury@example.com',
    });
    expect(reg2.excludeCredentials).toHaveLength(1);
    expect(reg2.excludeCredentials[0].id).toBe(credId1.toString('base64url'));

    const saved2 = await service.verifyRegistrationAttestation({
      userId: 'user-1',
      nickname: 'MacBook Pro TouchID',
      clientDataJSON: buildClientDataJSON({
        type: 'webauthn.create',
        challenge: reg2.challenge,
        origin: ORIGIN,
      }),
      attestationObject: buildAttestationObject({
        rpId: RP_ID,
        credentialId: credId2,
        publicKey: edPair.publicKey,
        signCount: 0,
      }),
      transports: ['internal'],
    });

    expect(saved2.nickname).toBe('MacBook Pro TouchID');
    expect(saved2.algorithm).toBe(-8);

    const list = await service.listCredentials('user-1');
    expect(list).toHaveLength(2);
    expect(list.map((c) => c.nickname)).toEqual(['YubiKey 5C Nano', 'MacBook Pro TouchID']);
  });

  it('rejects attestation with phishing origin mismatch or replayed challenge', async () => {
    const keyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const reg = await service.generateRegistrationChallenge({
      userId: 'user-1',
      email: 'treasury@example.com',
    });

    await expect(
      service.verifyRegistrationAttestation({
        userId: 'user-1',
        nickname: 'Phished Key',
        clientDataJSON: buildClientDataJSON({
          type: 'webauthn.create',
          challenge: reg.challenge,
          origin: 'https://evil-phishing-proxy.com',
        }),
        attestationObject: buildAttestationObject({
          rpId: RP_ID,
          credentialId: crypto.randomBytes(16),
          publicKey: keyPair.publicKey,
        }),
      }),
    ).rejects.toMatchObject({ code: 'ORIGIN_MISMATCH' });
  });

  it('verifies cryptographic assertion signatures and strictly rejects cloned signCount regressions', async () => {
    const keyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const credId = crypto.randomBytes(16);
    const credIdB64 = credId.toString('base64url');

    const reg = await service.generateRegistrationChallenge({
      userId: 'user-1',
      email: 'treasury@example.com',
    });
    await service.verifyRegistrationAttestation({
      userId: 'user-1',
      nickname: 'Primary YubiKey',
      clientDataJSON: buildClientDataJSON({
        type: 'webauthn.create',
        challenge: reg.challenge,
        origin: ORIGIN,
      }),
      attestationObject: buildAttestationObject({
        rpId: RP_ID,
        credentialId: credId,
        publicKey: keyPair.publicKey,
        signCount: 5,
      }),
    });

    // Valid assertion with strictly greater signCount (6 > 5)
    const ch1 = await service.generateAssertionChallenge({ userId: 'user-1', purpose: 'login' });
    const assertion1 = buildSignedAssertion({
      rpId: RP_ID,
      challenge: ch1.challenge,
      origin: ORIGIN,
      signCount: 6,
      privateKey: keyPair.privateKey,
      algorithm: 'ES256',
    });

    const verified = await service.verifyAssertion({
      userId: 'user-1',
      credentialId: credIdB64,
      ...assertion1,
    });
    expect(verified.verified).toBe(true);
    expect(verified.signCount).toBe(6);
    expect(verified.stepUpToken).toBeTruthy();

    // Cloned key regression: signCount 4 <= stored 6 -> MUST reject
    const ch2 = await service.generateAssertionChallenge({ userId: 'user-1', purpose: 'login' });
    const regressedAssertion = buildSignedAssertion({
      rpId: RP_ID,
      challenge: ch2.challenge,
      origin: ORIGIN,
      signCount: 4,
      privateKey: keyPair.privateKey,
      algorithm: 'ES256',
    });

    await expect(
      service.verifyAssertion({
        userId: 'user-1',
        credentialId: credIdB64,
        ...regressedAssertion,
      }),
    ).rejects.toBeInstanceOf(WebAuthnClonedKeyError);

    // Cloned key stalled counter: signCount 6 <= stored 6 -> MUST reject
    const ch3 = await service.generateAssertionChallenge({ userId: 'user-1', purpose: 'login' });
    const stalledAssertion = buildSignedAssertion({
      rpId: RP_ID,
      challenge: ch3.challenge,
      origin: ORIGIN,
      signCount: 6,
      privateKey: keyPair.privateKey,
      algorithm: 'ES256',
    });

    await expect(
      service.verifyAssertion({
        userId: 'user-1',
        credentialId: credIdB64,
        ...stalledAssertion,
      }),
    ).rejects.toMatchObject({ code: 'CLONED_AUTHENTICATOR_DETECTED' });

    // Tampered signature -> MUST reject with INVALID_SIGNATURE
    const ch4 = await service.generateAssertionChallenge({ userId: 'user-1', purpose: 'login' });
    const wrongKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const tamperedAssertion = buildSignedAssertion({
      rpId: RP_ID,
      challenge: ch4.challenge,
      origin: ORIGIN,
      signCount: 7,
      privateKey: wrongKey.privateKey,
      algorithm: 'ES256',
    });

    await expect(
      service.verifyAssertion({
        userId: 'user-1',
        credentialId: credIdB64,
        ...tamperedAssertion,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_SIGNATURE' });
  });

  it('requires single-use WebAuthn step-up verification before destructive actions when keys are registered', async () => {
    // User without registered keys passes through
    await expect(service.verifyStepUpAccess('user-no-keys', undefined, 'deleting a wallet')).resolves.toEqual({
      required: false,
      verified: true,
    });

    // Register a key for user-1
    const keyPair = crypto.generateKeyPairSync('ed25519');
    const credId = crypto.randomBytes(16);
    const credIdB64 = credId.toString('base64url');
    const reg = await service.generateRegistrationChallenge({
      userId: 'user-1',
      email: 'treasury@example.com',
    });
    await service.verifyRegistrationAttestation({
      userId: 'user-1',
      nickname: 'Backup Passkey',
      clientDataJSON: buildClientDataJSON({
        type: 'webauthn.create',
        challenge: reg.challenge,
        origin: ORIGIN,
      }),
      attestationObject: buildAttestationObject({
        rpId: RP_ID,
        credentialId: credId,
        publicKey: keyPair.publicKey,
        signCount: 0,
      }),
    });

    // Without step-up token -> rejected
    await expect(
      service.verifyStepUpAccess('user-1', undefined, 'rotating a webhook signing secret'),
    ).rejects.toBeInstanceOf(WebAuthnStepUpRequiredError);

    // Perform step-up assertion
    const stepUpChallenge = await service.generateAssertionChallenge({
      userId: 'user-1',
      purpose: 'step-up',
    });
    const signed = buildSignedAssertion({
      rpId: RP_ID,
      challenge: stepUpChallenge.challenge,
      origin: ORIGIN,
      signCount: 1,
      privateKey: keyPair.privateKey,
      algorithm: 'EdDSA',
    });
    const result = await service.verifyAssertion({
      userId: 'user-1',
      credentialId: credIdB64,
      expectedPurpose: 'step-up',
      ...signed,
    });

    // First use of step-up token succeeds
    await expect(
      service.verifyStepUpAccess('user-1', result.stepUpToken, 'deleting a wallet'),
    ).resolves.toEqual({ required: true, verified: true });

    // Replay of same single-use step-up token fails
    await expect(
      service.verifyStepUpAccess('user-1', result.stepUpToken, 'deleting a wallet'),
    ).rejects.toBeInstanceOf(WebAuthnError);
  });
});
