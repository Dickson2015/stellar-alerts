import { describe, it, expect, vi } from 'vitest';
import {
  MAX_WORKERS,
  MIN_WORKERS,
  WorkerScaler,
  type WorkerScalerOptions,
} from '../worker-scaler';

function createScaler(overrides: {
  depths?: Record<string, number>;
  lagMs?: number;
  memoryPressure?: number;
  initial?: number;
  options?: WorkerScalerOptions;
} = {}) {
  const depths = overrides.depths ?? { 'bull:queue:wait': 0 };
  const redis = {
    llen: vi.fn(async (key: string) => depths[key] ?? 0),
  } as any;
  const prometheus = { setWorkerConcurrency: vi.fn() };

  const scaler = new WorkerScaler(redis, overrides.initial ?? MIN_WORKERS, {
    workerName: 'test-worker',
    queueKeys: Object.keys(depths),
    eventLoopLagProvider: () => overrides.lagMs ?? 0,
    memoryPressureProvider: () => overrides.memoryPressure ?? 0.1,
    prometheus,
    now: () => 1_000_000,
    ...overrides.options,
  });

  return { scaler, redis, prometheus };
}

describe('WorkerScaler (#915)', () => {
  it('scales up when the queue backlog exceeds 500 and event loop lag is below 20ms', async () => {
    const { scaler, prometheus } = createScaler({
      depths: { 'bull:queue:wait': 750 },
      lagMs: 8,
    });

    const metrics = await scaler.collectMetrics();
    const decision = scaler.makeDecision();

    expect(metrics.redisQueueDepth).toBe(750);
    expect(decision.shouldScale).toBe(true);
    expect(decision.direction).toBe('scale_up');
    expect(decision.recommendedWorkers).toBe(10);
    expect(prometheus.setWorkerConcurrency).toHaveBeenCalledWith('test-worker', 5);

    expect(scaler.applyDecision(decision)).toBe(true);
    expect(scaler.getCurrentConcurrency()).toBe(10);
    expect(prometheus.setWorkerConcurrency).toHaveBeenLastCalledWith('test-worker', 10);
  });

  it('scales down when event loop lag exceeds 50ms', async () => {
    const { scaler } = createScaler({ lagMs: 75, initial: 20 });

    await scaler.collectMetrics();
    const decision = scaler.makeDecision();

    expect(decision.direction).toBe('scale_down');
    expect(decision.recommendedWorkers).toBe(17);
    expect(decision.reason).toMatch(/event loop lag/);
  });

  it('scales down when heap pressure exceeds 80%', async () => {
    const { scaler } = createScaler({ memoryPressure: 0.85, initial: 20 });

    await scaler.collectMetrics();
    const decision = scaler.makeDecision();

    expect(decision.direction).toBe('scale_down');
    expect(decision.recommendedWorkers).toBe(17);
    expect(decision.reason).toMatch(/memory pressure/);
  });

  it('never scales below the minimum or above the maximum', async () => {
    const atMin = createScaler({ lagMs: 100, initial: MIN_WORKERS }).scaler;
    await atMin.collectMetrics();
    expect(atMin.makeDecision().recommendedWorkers).toBe(MIN_WORKERS);

    const atMax = createScaler({ depths: { 'bull:queue:wait': 5_000 }, lagMs: 1, initial: 48 }).scaler;
    await atMax.collectMetrics();
    expect(atMax.makeDecision().recommendedWorkers).toBe(MAX_WORKERS);
  });

  it('respects the cooldown between scaling decisions', async () => {
    const { scaler } = createScaler({ depths: { 'bull:queue:wait': 900 }, lagMs: 5 });

    await scaler.collectMetrics();
    expect(scaler.applyDecision(scaler.makeDecision())).toBe(true);

    // Same injectable clock → the 30s cooldown is still active.
    await scaler.collectMetrics();
    const subsequent = scaler.makeDecision();

    expect(subsequent.shouldScale).toBe(false);
    expect(subsequent.reason).toMatch(/Cooldown/);
    expect(scaler.getCurrentConcurrency()).toBe(10);
  });

  it('sums backlog across every configured queue key and survives a Redis error', async () => {
    const redis = {
      llen: vi.fn(async (key: string) => {
        if (key === 'bull:broken:wait') throw new Error('redis down');
        return key === 'bull:a:wait' ? 200 : 350;
      }),
    } as any;

    const scaler = new WorkerScaler(redis, MIN_WORKERS, {
      queueKeys: ['bull:a:wait', 'bull:b:wait', 'bull:broken:wait'],
      eventLoopLagProvider: () => 1,
      memoryPressureProvider: () => 0.1,
      prometheus: { setWorkerConcurrency: vi.fn() },
    });

    const metrics = await scaler.collectMetrics();
    expect(metrics.redisQueueDepth).toBe(550);
    expect(scaler.makeDecision().direction).toBe('scale_up');
  });

  it('uses real process memory and perf_hooks event-loop delay by default', async () => {
    const scaler = new WorkerScaler({ llen: vi.fn(async () => 0) } as any, MIN_WORKERS, {
      prometheus: { setWorkerConcurrency: vi.fn() },
    });
    try {
      const metrics = await scaler.collectMetrics();
      expect(metrics.memoryPressure).toBeGreaterThan(0);
      expect(metrics.memoryPressure).toBeLessThanOrEqual(1);
      expect(metrics.eventLoopLagMs).toBeGreaterThanOrEqual(0);
      expect(metrics.eventLoopLagMs).toBeLessThan(1_000);
    } finally {
      scaler.stop();
    }
  });
});
