import { beforeEach, describe, expect, it, vi } from 'vitest';

const { redisStore, stellarMock } = vi.hoisted(() => ({
  redisStore: new Map<string, string>(),
  stellarMock: {
    getLatestOperationPagingToken: vi.fn(),
    getAccountDataEntries: vi.fn(),
    getAccountOperationsSince: vi.fn(),
  },
}));

vi.mock('../../../lib/prisma', () => ({ prisma: {} }));
vi.mock('../../../lib/stellar', () => ({ stellar: stellarMock }));
vi.mock('../../../lib/queue', () => ({ dispatchWebhookAndLog: vi.fn() }));
vi.mock('../../../lib/redis', () => ({
  redisCache: {
    get: async (key: string) => redisStore.get(key) ?? null,
    set: async (key: string, value: string) => {
      redisStore.set(key, value);
    },
    del: async (key: string) => (redisStore.delete(key) ? 1 : 0),
    setNx: async (key: string, value: string) => {
      if (redisStore.has(key)) return false;
      redisStore.set(key, value);
      return true;
    },
  },
}));

import {
  applyManageData,
  buildManageDataTelegramMessage,
  decodeDataValue,
  diffManageData,
  isProtectedDataKey,
  runManageDataSentinelPass,
  type ManageDataAlert,
  type ManageDataOperation,
} from '../manage-data-sentinel';

const ACCOUNT = 'GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H';
const b64 = (text: string) => Buffer.from(text, 'utf8').toString('base64');

const op = (overrides: Partial<ManageDataOperation>): ManageDataOperation => ({
  id: 'op-1',
  paging_token: '100',
  type: 'manage_data',
  source_account: ACCOUNT,
  name: 'app.setting',
  value: b64('v1'),
  created_at: '2026-11-23T10:00:00Z',
  transaction_hash: 'hash-1',
  ...overrides,
});

describe('decodeDataValue', () => {
  it('decodes printable UTF-8 alongside hex and base64', () => {
    expect(decodeDataValue(b64('héllo'))).toEqual({
      base64: b64('héllo'),
      hex: Buffer.from('héllo').toString('hex'),
      utf8: 'héllo',
    });
  });

  it.each([
    ['invalid UTF-8', Buffer.from([0xff, 0xfe, 0x00])],
    ['control characters', Buffer.from('a\u0000b')],
    ['bidi overrides', Buffer.from('safe‮evil')],
    ['zero-width characters', Buffer.from('a​b')],
  ])('withholds the UTF-8 form for %s', (_label, bytes) => {
    const decoded = decodeDataValue(bytes.toString('base64'));
    expect(decoded.utf8).toBeNull();
    expect(decoded.hex).toBe(bytes.toString('hex'));
  });
});

describe('isProtectedDataKey', () => {
  it.each(['config.memo_required', 'auth.domain', 'auth.', 'did.document', 'did.key.1'])('protects %s', (key) => {
    expect(isProtectedDataKey(key)).toBe(true);
  });

  it.each(['config.other', 'config.memo_required2', 'author', 'auth', 'didactic', 'x.auth.y', 'CONFIG.MEMO_REQUIRED'])(
    'does not protect %s',
    (key) => {
      expect(isProtectedDataKey(key)).toBe(false);
    },
  );
});

describe('diffManageData', () => {
  it('reports a creation with no before value', () => {
    const alert = diffManageData(op({}), new Map());
    expect(alert).toMatchObject({ change: 'CREATED', severity: 'INFO', before: null, after: { utf8: 'v1' } });
  });

  it('reports an update with before and after values', () => {
    const alert = diffManageData(op({ value: b64('v2') }), new Map([['app.setting', b64('v1')]]));
    expect(alert).toMatchObject({
      change: 'UPDATED',
      severity: 'WARNING',
      before: { base64: b64('v1'), utf8: 'v1' },
      after: { base64: b64('v2'), utf8: 'v2' },
    });
  });

  it.each([null, undefined, ''])('reports a deletion when the value is %s', (value) => {
    const alert = diffManageData(op({ value }), new Map([['app.setting', b64('v1')]]));
    expect(alert).toMatchObject({ change: 'DELETED', severity: 'WARNING', before: { utf8: 'v1' }, after: null });
  });

  it.each(['config.memo_required', 'auth.signer', 'did.document'])('is CRITICAL for changes to %s', (name) => {
    const state = new Map([[name, b64('1')]]);
    expect(diffManageData(op({ name, value: b64('0') }), state)?.severity).toBe('CRITICAL');
    expect(diffManageData(op({ name, value: null }), state)?.severity).toBe('CRITICAL');
  });

  it('is WARNING when a protected key is first created', () => {
    expect(diffManageData(op({ name: 'auth.signer' }), new Map())).toMatchObject({
      change: 'CREATED',
      severity: 'WARNING',
      protectedKey: true,
    });
  });

  it('ignores no-op writes, replayed deletions, failed transactions and other operations', () => {
    expect(diffManageData(op({}), new Map([['app.setting', b64('v1')]]))).toBeNull();
    expect(diffManageData(op({ value: null }), new Map())).toBeNull();
    expect(diffManageData(op({ transaction_successful: false }), new Map())).toBeNull();
    expect(diffManageData(op({ type: 'payment' }), new Map())).toBeNull();
  });

  it('handles a key named __proto__ without touching the prototype chain', () => {
    const state = new Map<string, string>();
    const created = op({ name: '__proto__', value: b64('x') });
    expect(diffManageData(created, state)?.change).toBe('CREATED');
    applyManageData(created, state);
    expect(state.get('__proto__')).toBe(b64('x'));
    expect(({} as Record<string, unknown>).x).toBeUndefined();
  });
});

describe('buildManageDataTelegramMessage', () => {
  it('escapes attacker-controlled keys and values', () => {
    const alert = diffManageData(op({ name: '<b>k</b>', value: b64('<script>') }), new Map()) as ManageDataAlert;
    const message = buildManageDataTelegramMessage(alert);
    expect(message).not.toContain('<script>');
    expect(message).toContain('&lt;b&gt;k&lt;/b&gt;');
  });
});

describe('runManageDataSentinelPass', () => {
  const notify = vi.fn<(alert: ManageDataAlert) => Promise<void>>();

  beforeEach(() => {
    redisStore.clear();
    vi.clearAllMocks();
    notify.mockResolvedValue(undefined);
    stellarMock.getLatestOperationPagingToken.mockResolvedValue({ ok: true, token: '50' });
    stellarMock.getAccountDataEntries.mockResolvedValue({ 'config.memo_required': b64('1') });
    stellarMock.getAccountOperationsSince.mockResolvedValue({ ok: true, records: [] });
  });

  it('seeds state on first sight without alerting on history', async () => {
    await expect(runManageDataSentinelPass([ACCOUNT], notify)).resolves.toBe(0);
    expect(notify).not.toHaveBeenCalled();
    expect(stellarMock.getAccountOperationsSince).not.toHaveBeenCalled();
  });

  it('diffs against seeded state and tracks later changes', async () => {
    await runManageDataSentinelPass([ACCOUNT], notify);
    stellarMock.getAccountOperationsSince.mockResolvedValue({
      ok: true,
      records: [
        op({ id: 'op-2', paging_token: '60', name: 'config.memo_required', value: null }),
        op({ id: 'op-3', paging_token: '61', name: 'config.memo_required', value: b64('1') }),
      ],
    });

    await expect(runManageDataSentinelPass([ACCOUNT], notify)).resolves.toBe(2);
    expect(notify.mock.calls[0]?.[0]).toMatchObject({ change: 'DELETED', severity: 'CRITICAL' });
    expect(notify.mock.calls[1]?.[0]).toMatchObject({ change: 'CREATED', before: null });
    expect(stellarMock.getAccountOperationsSince).toHaveBeenLastCalledWith(ACCOUNT, '50', 100);

    stellarMock.getAccountOperationsSince.mockResolvedValue({ ok: true, records: [] });
    await runManageDataSentinelPass([ACCOUNT], notify);
    expect(stellarMock.getAccountOperationsSince).toHaveBeenLastCalledWith(ACCOUNT, '61', 100);
  });

  it('ignores data operations sourced by another account', async () => {
    await runManageDataSentinelPass([ACCOUNT], notify);
    stellarMock.getAccountOperationsSince.mockResolvedValue({
      ok: true,
      records: [op({ source_account: 'GOTHER', name: 'auth.x' })],
    });
    await expect(runManageDataSentinelPass([ACCOUNT], notify)).resolves.toBe(0);
  });

  it('retries the same operation after a delivery failure, then alerts once', async () => {
    await runManageDataSentinelPass([ACCOUNT], notify);
    const record = op({ id: 'op-2', paging_token: '60', name: 'config.memo_required', value: null });
    stellarMock.getAccountOperationsSince.mockResolvedValue({ ok: true, records: [record] });

    notify.mockRejectedValueOnce(new Error('delivery down'));
    await expect(runManageDataSentinelPass([ACCOUNT], notify)).resolves.toBe(0);
    expect(stellarMock.getAccountOperationsSince).toHaveBeenLastCalledWith(ACCOUNT, '50', 100);

    await expect(runManageDataSentinelPass([ACCOUNT], notify)).resolves.toBe(1);
    expect(notify).toHaveBeenCalledTimes(2);
  });
});
