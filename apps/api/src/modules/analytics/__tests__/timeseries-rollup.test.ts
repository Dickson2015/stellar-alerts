import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  TimeSeriesRollupEngine,
  type TimeSeriesRollupStore,
} from '../timeseries-rollup';

function createStore() {
  const rows = new Map<string, {
    asset: string;
    interval: string;
    bucketStart: Date;
    count: number;
    volume: number;
    minAmount: number;
    maxAmount: number;
    senders: Set<string>;
  }>();
  const store: TimeSeriesRollupStore = {
    upsert: vi.fn(async (increment) => {
      const key = `${increment.asset}:${increment.interval}:${increment.bucketStart}`;
      const existing = rows.get(key);
      if (existing) {
        existing.count += increment.count;
        existing.volume += increment.volume;
        existing.minAmount = Math.min(existing.minAmount, increment.minAmount);
        existing.maxAmount = Math.max(existing.maxAmount, increment.maxAmount);
        for (const sender of increment.senders) existing.senders.add(sender);
      } else {
        rows.set(key, {
          asset: increment.asset,
          interval: increment.interval,
          bucketStart: new Date(increment.bucketStart),
          count: increment.count,
          volume: increment.volume,
          minAmount: increment.minAmount,
          maxAmount: increment.maxAmount,
          senders: new Set(increment.senders),
        });
      }
    }),
    query: vi.fn(async () => []),
  };
  return { rows, store };
}

describe('TimeSeriesRollupEngine', () => {
  let rows: ReturnType<typeof createStore>['rows'];
  let store: TimeSeriesRollupStore;
  let engine: TimeSeriesRollupEngine;

  beforeEach(() => {
    ({ rows, store } = createStore());
    engine = new TimeSeriesRollupEngine(store);
  });

  it('aggregates tumbling 1m, 5m, and 1h windows with unique senders', async () => {
    const time = Date.UTC(2026, 0, 1, 0, 4, 57);
    engine.record({ amount: '3.5', asset: 'USD', assetIssuer: 'GISSUER', fromAddress: 'GONE', receivedAt: time });
    engine.record({ amount: 8, asset: 'USD', assetIssuer: 'GISSUER', fromAddress: 'GONE', receivedAt: time + 1 });
    engine.record({ amount: 2, asset: 'USD', assetIssuer: 'GISSUER', fromAddress: 'GTWO', receivedAt: time + 2 });
    await engine.flush();

    const oneMinute = rows.get(`USD:GISSUER:1m:${Date.UTC(2026, 0, 1, 0, 4)}`);
    const fiveMinute = rows.get(`USD:GISSUER:5m:${Date.UTC(2026, 0, 1, 0, 0)}`);
    const oneHour = rows.get(`USD:GISSUER:1h:${Date.UTC(2026, 0, 1, 0, 0)}`);
    expect(oneMinute).toMatchObject({ count: 3, volume: 13.5, minAmount: 2, maxAmount: 8 });
    expect(oneMinute?.senders.size).toBe(2);
    expect(fiveMinute).toMatchObject({ count: 3, volume: 13.5, minAmount: 2, maxAmount: 8 });
    expect(oneHour).toMatchObject({ count: 3, volume: 13.5, minAmount: 2, maxAmount: 8 });
  });

  it('upserts late events into the original historical bucket', async () => {
    const lateTime = Date.UTC(2026, 0, 1, 0, 2, 15);
    engine.record({ amount: 10, asset: 'XLM', fromAddress: 'GA', receivedAt: lateTime });
    await engine.flush();

    engine.record({ amount: 5, asset: 'XLM', fromAddress: 'GB', receivedAt: lateTime - 90_000 });
    await engine.flush();

    const minuteBucket = rows.get(`XLM:native:1m:${Date.UTC(2026, 0, 1, 0, 2)}`);
    const fiveMinuteBucket = rows.get(`XLM:native:5m:${Date.UTC(2026, 0, 1, 0, 0)}`);
    expect(minuteBucket).toMatchObject({ count: 1, volume: 10 });
    expect(fiveMinuteBucket).toMatchObject({ count: 2, volume: 15, minAmount: 5, maxAmount: 10 });
    expect(fiveMinuteBucket?.senders.size).toBe(2);
  });

  it('retains failed increments and merges new events before retrying', async () => {
    const upsert = vi.fn()
      .mockRejectedValueOnce(new Error('database unavailable'))
      .mockResolvedValue(undefined);
    const failingStore: TimeSeriesRollupStore = { upsert, query: vi.fn(async () => []) };
    const retryEngine = new TimeSeriesRollupEngine(failingStore);
    const receivedAt = Date.UTC(2026, 0, 1);
    retryEngine.record({ amount: 2, asset: 'XLM', fromAddress: 'GA', receivedAt });
    await expect(retryEngine.flush()).rejects.toThrow('database unavailable');

    retryEngine.record({ amount: 4, asset: 'XLM', fromAddress: 'GB', receivedAt });
    await retryEngine.flush();

    expect(upsert).toHaveBeenLastCalledWith(expect.objectContaining({
      count: 2,
      volume: 6,
      minAmount: 2,
      maxAmount: 4,
      senders: new Set(['GA', 'GB']),
    }));
  });

  it('rejects invalid payment data and invalid historical ranges', async () => {
    expect(() => engine.record({
      amount: Number.NaN, asset: 'XLM', fromAddress: 'GA', receivedAt: Date.now(),
    })).toThrow(/amount/);
    await expect(engine.query({
      interval: '1m',
      from: new Date('2026-01-02T00:00:00Z'),
      to: new Date('2026-01-01T00:00:00Z'),
    })).rejects.toThrow(/range/);
  });

  it('caps historical queries to one thousand buckets', async () => {
    await engine.query({
      interval: '1h',
      from: new Date('2026-01-01T00:00:00Z'),
      to: new Date('2026-01-02T00:00:00Z'),
      limit: 5000,
    });
    expect(store.query).toHaveBeenCalledWith(expect.objectContaining({ limit: 1000 }));
  });
});
