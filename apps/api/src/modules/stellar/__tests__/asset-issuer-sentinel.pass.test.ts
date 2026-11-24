import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  get: vi.fn<(...args: unknown[]) => Promise<string | null>>(),
  set: vi.fn<(...args: unknown[]) => Promise<void>>(),
  setNx: vi.fn<(...args: unknown[]) => Promise<boolean>>(),
  latestToken: vi.fn<(...args: unknown[]) => Promise<{ ok: boolean; token: string | null }>>(),
  operations: vi.fn<(...args: unknown[]) => Promise<{ ok: boolean; records: unknown[] }>>(),
}));

vi.mock('../../../lib/prisma', () => ({ prisma: {} }));
vi.mock('../../../lib/stellar', () => ({
  stellar: {
    getLatestOperationPagingToken: mocks.latestToken,
    getAccountOperationsSince: mocks.operations,
  },
}));
vi.mock('../../../lib/redis', () => ({
  redisCache: { get: mocks.get, set: mocks.set, setNx: mocks.setNx },
}));
vi.mock('../../../lib/queue', () => ({ dispatchWebhookAndLog: vi.fn() }));

import {
  AssetIssuerSentinel,
  runAssetIssuerSentinelPass,
  type AssetIssuerAlert,
} from '../asset-issuer-sentinel';

const ISSUER = 'GISSUERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

describe('runAssetIssuerSentinelPass (#1035)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.get.mockResolvedValue(null);
    mocks.set.mockResolvedValue(undefined);
    mocks.setNx.mockResolvedValue(true);
    mocks.latestToken.mockResolvedValue({ ok: true, token: '100' });
    mocks.operations.mockResolvedValue({ ok: true, records: [] });
  });

  it('seeds the cursor on first sight without replaying history', async () => {
    const notify = vi.fn();
    const emitted = await runAssetIssuerSentinelPass(
      [],
      notify,
      { loadIssuers: async () => [{ issuer: ISSUER }], sentinel: new AssetIssuerSentinel() },
    );

    expect(emitted).toBe(0);
    expect(mocks.latestToken).toHaveBeenCalledWith(ISSUER);
    expect(mocks.set).toHaveBeenCalledWith(`asset-issuer-sentinel:cursor:${ISSUER}`, '100');
    expect(notify).not.toHaveBeenCalled();
  });

  it('assesses new operations, emits once and advances the cursor', async () => {
    mocks.get.mockResolvedValue('100');
    mocks.operations.mockResolvedValue({
      ok: true,
      records: [{
        id: 'op-1',
        paging_token: '105',
        type: 'payment',
        transaction_hash: 'tx-1',
        created_at: '2026-11-24T10:00:00.000Z',
        from: ISSUER,
        asset_code: 'USD',
        asset_issuer: ISSUER,
        amount: '25',
      }],
    });
    const notify = vi.fn<(alert: AssetIssuerAlert) => void>();

    const emitted = await runAssetIssuerSentinelPass(
      [],
      notify,
      { loadIssuers: async () => [{ issuer: ISSUER }], sentinel: new AssetIssuerSentinel() },
    );

    expect(emitted).toBe(1);
    expect(notify).toHaveBeenCalledWith(expect.objectContaining({ eventType: 'ISSUANCE' }));
    expect(mocks.setNx).toHaveBeenCalledWith(
      `asset-issuer-sentinel:alert:op-1:${ISSUER}:ISSUANCE`,
      '1',
      30 * 24 * 60 * 60,
    );
    expect(mocks.set).toHaveBeenCalledWith(`asset-issuer-sentinel:cursor:${ISSUER}`, '105');
  });

  it('suppresses duplicate alerts but still advances the cursor', async () => {
    mocks.get.mockResolvedValue('100');
    mocks.setNx.mockResolvedValue(false);
    mocks.operations.mockResolvedValue({
      ok: true,
      records: [{
        id: 'op-1',
        paging_token: '105',
        type: 'set_options',
        source_account: ISSUER,
        set_flags: [2],
      }],
    });
    const notify = vi.fn();

    const emitted = await runAssetIssuerSentinelPass(
      [],
      notify,
      { loadIssuers: async () => [{ issuer: ISSUER }], sentinel: new AssetIssuerSentinel() },
    );

    expect(emitted).toBe(0);
    expect(notify).not.toHaveBeenCalled();
    expect(mocks.set).toHaveBeenCalledWith(`asset-issuer-sentinel:cursor:${ISSUER}`, '105');
  });

  it('isolates a failing issuer scan and returns no alerts for an empty registry', async () => {
    mocks.get.mockRejectedValue(new Error('redis down'));
    const notify = vi.fn();

    await expect(runAssetIssuerSentinelPass(
      [],
      notify,
      { loadIssuers: async () => [{ issuer: ISSUER }], sentinel: new AssetIssuerSentinel() },
    )).resolves.toBe(0);
    expect(notify).not.toHaveBeenCalled();

    await expect(runAssetIssuerSentinelPass([], notify, { loadIssuers: async () => [] })).resolves.toBe(0);
  });
});
