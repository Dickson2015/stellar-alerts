import { EventEmitter } from 'events';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../lib/redis', () => ({
  getRedisClient: vi.fn(),
  registerRedisCleanupTask: vi.fn(),
}));
vi.mock('../../../lib/prisma', () => ({
  prisma: { wallet: { findFirst: vi.fn() } },
}));
vi.mock('../../middleware/auth.middleware', () => ({
  authenticateHook: vi.fn(),
  authenticateToken: vi.fn(),
}));

import {
  AlertStreamHub,
  MAX_REPLAY_EVENTS,
  eventMatchesFilters,
  formatAlertFrame,
  handleAlertStream,
  parseStreamFilters,
  type AlertStreamEvent,
  type StreamReplyLike,
  type StreamRequestLike,
} from '../sse-stream.controller';
import { prisma } from '../../../lib/prisma';

const USER = 'user-1';

function event(id: string, overrides: Partial<AlertStreamEvent> = {}): AlertStreamEvent {
  return {
    id,
    userId: USER,
    event: 'alert',
    severity: 'HIGH',
    walletId: 'wallet-1',
    payload: { event: 'payment.received', data: { id } },
    timestamp: '2026-11-24T10:00:00.000Z',
    ...overrides,
  };
}

function request(query: Record<string, unknown> = {}, lastEventId?: string) {
  const raw = new EventEmitter();
  return {
    value: {
      user: { id: USER },
      headers: lastEventId ? { 'last-event-id': lastEventId } : {},
      query,
      raw,
    } as unknown as StreamRequestLike,
    close: () => raw.emit('close'),
  };
}

function reply() {
  const writes: string[] = [];
  const value: StreamReplyLike = {
    hijack: vi.fn(),
    raw: {
      writeHead: vi.fn(),
      write: (chunk: string) => {
        writes.push(chunk);
        return true;
      },
    },
    status: vi.fn(() => value),
    send: vi.fn(() => value),
  };
  return { value, writes, headers: value.raw.writeHead as unknown as ReturnType<typeof vi.fn> };
}

function frames(writes: string[]): AlertStreamEvent[] {
  return writes
    .filter((chunk) => chunk.startsWith('id: '))
    .map((chunk) => JSON.parse(chunk.split('data: ')[1].split('\n')[0]) as AlertStreamEvent);
}

describe('SSE stream helpers (#1038)', () => {
  it('parses severity lists, wallet filters and Last-Event-ID', () => {
    expect(parseStreamFilters(
      { severity: ' critical ,HIGH', walletId: 'wallet-2' },
      '100-3',
    )).toEqual({
      severities: ['CRITICAL', 'HIGH'],
      walletId: 'wallet-2',
      lastEventId: '100-3',
    });
    expect(parseStreamFilters({}).severities).toEqual([]);
  });

  it('formats id/event/data frames and matches per-connection filters', () => {
    const sample = event('100-1');
    expect(formatAlertFrame(sample)).toBe(
      `id: 100-1\nevent: alert\ndata: ${JSON.stringify(sample)}\n\n`,
    );

    expect(eventMatchesFilters(sample, { severities: ['CRITICAL', 'HIGH'], walletId: 'wallet-1' })).toBe(true);
    expect(eventMatchesFilters(sample, { severities: ['LOW'], walletId: 'wallet-1' })).toBe(false);
    expect(eventMatchesFilters(sample, { severities: [], walletId: 'wallet-other' })).toBe(false);
  });
});

describe('AlertStreamHub (#1038)', () => {
  it('de-duplicates Redis echoes and bounds each tenant buffer', () => {
    const hub = new AlertStreamHub();
    expect(hub.ingest(event('100-1'))).toBe(true);
    expect(hub.ingest(event('100-1'))).toBe(false);

    for (let index = 2; index <= MAX_REPLAY_EVENTS + 5; index += 1) {
      hub.ingest(event(`100-${index}`));
    }
    expect(hub.bufferedCount(USER)).toBe(MAX_REPLAY_EVENTS);
    expect(hub.replay(USER)[0].id).toBe('100-6');
  });
});

describe('GET /api/v1/alerts/stream handler (#1038)', () => {
  let hub: AlertStreamHub;

  beforeEach(() => {
    hub = new AlertStreamHub();
    vi.mocked(prisma.wallet.findFirst).mockResolvedValue({ id: 'wallet-1' } as never);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('sends SSE headers and a connected frame on connect', async () => {
    const req = request();
    const res = reply();
    const pending = handleAlertStream(req.value, res.value, { hub, heartbeatMs: 60_000 });
    req.close();
    await pending;

    expect(res.value.hijack).toHaveBeenCalledOnce();
    expect(res.headers).toHaveBeenCalledWith(200, expect.objectContaining({
      'Content-Type': 'text/event-stream',
      'X-Accel-Buffering': 'no',
    }));
    expect(res.writes[0]).toContain('event: connected');
  });

  it('replays all five missed events in order using Last-Event-ID', async () => {
    for (let index = 1; index <= 6; index += 1) hub.ingest(event(`100-${index}`));

    const req = request({ severity: 'HIGH' }, '100-1');
    const res = reply();
    const pending = handleAlertStream(req.value, res.value, { hub, heartbeatMs: 60_000 });
    req.close();
    await pending;

    expect(frames(res.writes).map((entry) => entry.id)).toEqual(['100-2', '100-3', '100-4', '100-5', '100-6']);
  });

  it('fans out live events to connected subscribers but not other tenants', async () => {
    const req = request();
    const res = reply();
    const pending = handleAlertStream(req.value, res.value, { hub, heartbeatMs: 60_000 });

    hub.ingest(event('100-1'));
    hub.ingest(event('100-2', { userId: 'other-user' }));
    req.close();
    await pending;

    expect(frames(res.writes).map((entry) => entry.id)).toEqual(['100-1']);
  });

  it('applies wallet and severity filters to replayed events', async () => {
    hub.ingest(event('100-1', { severity: 'LOW' }));
    hub.ingest(event('100-2', { severity: 'CRITICAL', walletId: 'wallet-2' }));
    hub.ingest(event('100-3', { severity: 'CRITICAL' }));

    const req = request({ severity: 'CRITICAL', walletId: 'wallet-1' });
    const res = reply();
    const pending = handleAlertStream(req.value, res.value, { hub, heartbeatMs: 60_000 });
    await vi.waitFor(() => expect(res.value.hijack).toHaveBeenCalled());
    req.close();
    await pending;

    expect(frames(res.writes).map((entry) => entry.id)).toEqual(['100-3']);
    expect(prisma.wallet.findFirst).toHaveBeenCalledWith({
      where: { id: 'wallet-1', userId: USER, deletedAt: null },
      select: { id: true },
    });
  });

  it('refuses a wallet the authenticated user does not own', async () => {
    vi.mocked(prisma.wallet.findFirst).mockResolvedValue(null);
    const req = request({ walletId: 'foreign-wallet' });
    const res = reply();

    await handleAlertStream(req.value, res.value, { hub });

    expect(res.value.status).toHaveBeenCalledWith(403);
    expect(res.value.hijack).not.toHaveBeenCalled();
  });

  it('emits heartbeat comments while connected and removes its listener on close', async () => {
    vi.useFakeTimers();
    try {
      const req = request();
      const res = reply();
      const pending = handleAlertStream(req.value, res.value, { hub, heartbeatMs: 15_000 });
      vi.advanceTimersByTime(45_000);
      req.close();
      await pending;

      expect(res.writes.filter((chunk) => chunk === ': heartbeat\n\n')).toHaveLength(3);
      expect(hub.ingest(event('100-1'))).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});
