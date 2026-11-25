/**
 * Dispatch-level integration for encrypted webhook delivery (#929): the
 * worker must replace the JSON body with an ECIES envelope and publish the
 * ephemeral key, and must fail closed when encryption is impossible.
 */
import nacl from 'tweetnacl';
import { describe, it, expect, vi } from 'vitest';
import { DispatcherWorker } from '../dispatcher.worker';
import {
  STELLAR_ALERTS_EPHEMERAL_KEY_HEADER,
  decryptEciesPayload,
  type EciesEncryptedEnvelope,
} from '../../utils/ecies';

function fakeFilter() {
  return {
    validateAndResolve: async (url: string) => ({
      originalUrl: url,
      parsedUrl: new URL(url),
      hostname: new URL(url).hostname,
      pinnedIp: '93.184.216.34',
      family: 4 as const,
      resolvedIps: ['93.184.216.34'],
      pinnedUrl: url,
      hostHeader: new URL(url).hostname,
    }),
  } as any;
}

function fakeBreaker() {
  return {
    canExecute: vi.fn().mockResolvedValue(true),
    execute: vi.fn(async (_id: string, fn: () => Promise<any>) => fn()),
  } as any;
}

const payload = {
  event: 'payment.received',
  data: { txHash: 'b'.repeat(64), amount: '5.0000000' },
};

describe('DispatcherWorker ECIES delivery (#929)', () => {
  it('encrypts the payload and publishes the ephemeral key header', async () => {
    const recipient = nacl.box.keyPair();
    const transport = vi.fn(async () => ({ status: 200 }));
    const worker = new DispatcherWorker(fakeBreaker(), transport, fakeFilter());

    const result = await worker.processJob({
      data: {
        webhookId: 'wh-encrypted',
        url: 'https://alerts.example.com/hook',
        payload,
        encryptionPublicKey: Buffer.from(recipient.publicKey).toString('base64'),
      },
    });

    expect(result.status).toBe('delivered');
    expect(result.encrypted).toBe(true);
    expect(transport).toHaveBeenCalledTimes(1);

    const [, body, headers] = transport.mock.calls[0];
    const envelope = JSON.parse(body) as EciesEncryptedEnvelope;
    expect(envelope.v).toBe(1);
    expect(envelope.curve).toBe('x25519');
    expect(headers[STELLAR_ALERTS_EPHEMERAL_KEY_HEADER]).toBe(envelope.epk);
    expect(
      JSON.parse(
        decryptEciesPayload(envelope, Buffer.from(recipient.secretKey).toString('base64')),
      ),
    ).toEqual(payload);
  });

  it('fails closed for an unusable recipient key without calling the transport', async () => {
    const transport = vi.fn(async () => ({ status: 200 }));
    const worker = new DispatcherWorker(fakeBreaker(), transport, fakeFilter());

    const result = await worker.processJob({
      data: {
        webhookId: 'wh-bad-key',
        url: 'https://alerts.example.com/hook',
        payload,
        encryptionPublicKey: 'not-a-key',
      },
    });

    expect(result).toMatchObject({
      status: 'failed',
      reason: 'ecies_encryption_failed',
    });
    expect(transport).not.toHaveBeenCalled();
  });

  it('leaves plaintext deliveries untouched', async () => {
    const transport = vi.fn(async () => ({ status: 200 }));
    const worker = new DispatcherWorker(fakeBreaker(), transport, fakeFilter());

    const result = await worker.processJob({
      data: {
        webhookId: 'wh-plain',
        url: 'https://alerts.example.com/hook',
        payload,
      },
    });

    expect(result.encrypted).toBeUndefined();
    const [, body, headers] = transport.mock.calls[0];
    expect(JSON.parse(body)).toEqual(payload);
    expect(headers[STELLAR_ALERTS_EPHEMERAL_KEY_HEADER]).toBeUndefined();
  });
});
