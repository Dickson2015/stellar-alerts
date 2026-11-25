/**
 * WorkerScaler (#915)
 *
 * Dynamic adaptive worker auto-scaler driven by BullMQ queue backlog, Node
 * event-loop delay and heap pressure. Concurrency is bounded to
 * [MIN_WORKERS, MAX_WORKERS] and every applied decision is exported to
 * Prometheus as `stellar_alerts_worker_concurrency`.
 */

import { EventEmitter } from 'events';
import { monitorEventLoopDelay, type IntervalHistogram } from 'perf_hooks';
import Redis from 'ioredis';
import { createLogger } from './logger';
import { prometheusMetricsService } from '../modules/metrics/prometheus.service';

const log = createLogger({ module: 'WorkerScaler' });

/** Minimum worker concurrency */
export const MIN_WORKERS = 5;
/** Maximum worker concurrency */
export const MAX_WORKERS = 50;
/** Target event loop lag threshold in ms (below = healthy to scale up) */
export const TARGET_EVENT_LOOP_LAG_MS = 20;
/** Event loop lag above which concurrency is reduced (ms) */
export const MAX_EVENT_LOOP_LAG_MS = 50;
/** Heap-used ratio above which concurrency is reduced */
export const MEMORY_PRESSURE_THRESHOLD = 0.8;
/** Redis queue backlog depth threshold before scaling up */
export const QUEUE_BACKLOG_THRESHOLD = 500;
/** Cool-down period between scale decisions (ms) */
export const SCALE_COOLDOWN_MS = 30_000;

/** BullMQ `wait` list keys the default scaler inspects. */
export const DEFAULT_QUEUE_KEYS = ['bull:default:wait'];

/** Workers added per scale-up decision. */
const SCALE_UP_STEP = 5;
/** Workers removed per scale-down decision. */
const SCALE_DOWN_STEP = 3;

export type ScalingDirection = 'none' | 'scale_up' | 'scale_down';

export interface ScalingMetrics {
  redisQueueDepth: number;
  eventLoopLagMs: number;
  /** Heap used / heap total, 0.0 - 1.0 */
  memoryPressure: number;
  currentWorkers: number;
  timestamp: number;
}

export interface ScalingDecision {
  shouldScale: boolean;
  direction: ScalingDirection;
  recommendedWorkers: number;
  reason: string;
}

export interface WorkerScalerOptions {
  /** Label used for logs and the Prometheus gauge. */
  workerName?: string;
  /** BullMQ wait keys summed into the backlog depth. */
  queueKeys?: string[];
  /** Override event-loop lag collection (tests). */
  eventLoopLagProvider?: () => number;
  /** Override memory pressure collection (tests). */
  memoryPressureProvider?: () => number;
  /** Injectable clock (tests). */
  now?: () => number;
  /** Injectable metrics sink (tests). */
  prometheus?: { setWorkerConcurrency(worker: string, concurrency: number): void };
}

interface ScalerState {
  currentConcurrency: number;
  lastScaleDecision: number;
  lastMetrics: ScalingMetrics | null;
}

function clamp(value: number): number {
  return Math.min(Math.max(Math.round(value), MIN_WORKERS), MAX_WORKERS);
}

export class WorkerScaler extends EventEmitter {
  private readonly redis: Redis;
  private readonly workerName: string;
  private readonly queueKeys: string[];
  private readonly now: () => number;
  private readonly prometheus: { setWorkerConcurrency(worker: string, concurrency: number): void };
  private readonly eventLoopLagProvider?: () => number;
  private readonly memoryPressureProvider?: () => number;
  private readonly loopMonitor: IntervalHistogram | null = null;
  private state: ScalerState;
  private timer: NodeJS.Timeout | null = null;

  constructor(redis: Redis, initialConcurrency = MIN_WORKERS, options: WorkerScalerOptions = {}) {
    super();
    this.redis = redis;
    this.workerName = options.workerName ?? 'worker';
    this.queueKeys = options.queueKeys ?? DEFAULT_QUEUE_KEYS;
    this.now = options.now ?? Date.now;
    this.prometheus = options.prometheus ?? prometheusMetricsService;
    this.eventLoopLagProvider = options.eventLoopLagProvider;
    this.memoryPressureProvider = options.memoryPressureProvider;

    if (!this.eventLoopLagProvider) {
      this.loopMonitor = monitorEventLoopDelay({ resolution: 10 });
      this.loopMonitor.enable();
    }

    this.state = {
      currentConcurrency: clamp(initialConcurrency),
      lastScaleDecision: 0,
      lastMetrics: null,
    };
  }

  /** Reads mean event-loop delay (ms) over the interval since the last read. */
  private readEventLoopLagMs(): number {
    if (this.eventLoopLagProvider) return this.eventLoopLagProvider();
    if (!this.loopMonitor) return 0;
    // perf_hooks exposes nanoseconds; reset() makes each read an interval mean.
    const meanNs = this.loopMonitor.mean;
    this.loopMonitor.reset();
    const ms = meanNs / 1e6;
    return Number.isFinite(ms) ? Math.round(ms * 100) / 100 : 0;
  }

  private readMemoryPressure(): number {
    if (this.memoryPressureProvider) return this.memoryPressureProvider();
    const { heapTotal, heapUsed } = process.memoryUsage();
    return heapTotal > 0 ? heapUsed / heapTotal : 0;
  }

  private async readQueueDepth(): Promise<number> {
    let total = 0;
    for (const key of this.queueKeys) {
      try {
        const depth = await this.redis.llen(key);
        if (typeof depth === 'number' && Number.isFinite(depth)) total += depth;
      } catch (err) {
        log.warn({ err, key }, '⚠️ Failed to read Redis queue depth');
      }
    }
    return total;
  }

  /** Collects the metrics that drive the next scaling decision. */
  async collectMetrics(): Promise<ScalingMetrics> {
    const metrics: ScalingMetrics = {
      redisQueueDepth: await this.readQueueDepth(),
      eventLoopLagMs: this.readEventLoopLagMs(),
      memoryPressure: this.readMemoryPressure(),
      currentWorkers: this.state.currentConcurrency,
      timestamp: this.now(),
    };

    this.state.lastMetrics = metrics;
    this.prometheus.setWorkerConcurrency(this.workerName, metrics.currentWorkers);
    return metrics;
  }

  /** Makes a scaling decision from the most recently collected metrics. */
  makeDecision(): ScalingDecision {
    const metrics = this.state.lastMetrics;
    if (!metrics) {
      return {
        shouldScale: false,
        direction: 'none',
        recommendedWorkers: this.state.currentConcurrency,
        reason: 'No metrics available yet',
      };
    }

    const { redisQueueDepth, eventLoopLagMs, memoryPressure } = metrics;
    const currentConcurrency = this.state.currentConcurrency;
    const now = this.now();

    if (now - this.state.lastScaleDecision < SCALE_COOLDOWN_MS) {
      return {
        shouldScale: false,
        direction: 'none',
        recommendedWorkers: currentConcurrency,
        reason: `Cooldown active (${SCALE_COOLDOWN_MS - (now - this.state.lastScaleDecision)}ms remaining)`,
      };
    }

    if (memoryPressure > MEMORY_PRESSURE_THRESHOLD || eventLoopLagMs > MAX_EVENT_LOOP_LAG_MS) {
      return {
        shouldScale: true,
        direction: 'scale_down',
        recommendedWorkers: clamp(currentConcurrency - SCALE_DOWN_STEP),
        reason:
          memoryPressure > MEMORY_PRESSURE_THRESHOLD
            ? `memory pressure ${(memoryPressure * 100).toFixed(1)}% > ${(MEMORY_PRESSURE_THRESHOLD * 100).toFixed(0)}%`
            : `event loop lag ${eventLoopLagMs}ms > ${MAX_EVENT_LOOP_LAG_MS}ms`,
      };
    }

    if (redisQueueDepth > QUEUE_BACKLOG_THRESHOLD && eventLoopLagMs < TARGET_EVENT_LOOP_LAG_MS) {
      return {
        shouldScale: true,
        direction: 'scale_up',
        recommendedWorkers: clamp(currentConcurrency + SCALE_UP_STEP),
        reason: `queue backlog ${redisQueueDepth} > ${QUEUE_BACKLOG_THRESHOLD} and event loop lag ${eventLoopLagMs}ms < ${TARGET_EVENT_LOOP_LAG_MS}ms`,
      };
    }

    // Healthy, shallow queue and headroom: step back down gradually so a
    // single traffic burst doesn't leave the pool overprovisioned forever.
    if (redisQueueDepth < QUEUE_BACKLOG_THRESHOLD / 2 && currentConcurrency > MIN_WORKERS) {
      return {
        shouldScale: true,
        direction: 'scale_down',
        recommendedWorkers: clamp(currentConcurrency - SCALE_DOWN_STEP),
        reason: `queue backlog ${redisQueueDepth} is shallow and event loop lag ${eventLoopLagMs}ms is healthy`,
      };
    }

    return {
      shouldScale: false,
      direction: 'none',
      recommendedWorkers: currentConcurrency,
      reason: 'metrics within normal ranges',
    };
  }

  /** Applies a decision, updating state, metrics and emitting `scale`. */
  applyDecision(decision: ScalingDecision): boolean {
    if (!decision.shouldScale || decision.recommendedWorkers === this.state.currentConcurrency) {
      return false;
    }

    const previousConcurrency = this.state.currentConcurrency;
    this.state.currentConcurrency = clamp(decision.recommendedWorkers);
    this.state.lastScaleDecision = this.now();
    this.prometheus.setWorkerConcurrency(this.workerName, this.state.currentConcurrency);

    this.emit(
      'scale',
      previousConcurrency,
      this.state.currentConcurrency,
      decision.direction,
      decision.reason,
    );

    log.info(
      {
        worker: this.workerName,
        previousConcurrency,
        newConcurrency: this.state.currentConcurrency,
        direction: decision.direction,
        reason: decision.reason,
      },
      '⚖️ Adjusted worker concurrency',
    );

    return true;
  }

  /** Collects metrics, decides, and applies the decision in one pass. */
  async runScalingCycle(): Promise<ScalingDecision> {
    await this.collectMetrics();
    const decision = this.makeDecision();
    if (decision.shouldScale) this.applyDecision(decision);
    return decision;
  }

  /** Starts the periodic scaling loop. The timer does not keep the process alive. */
  start(intervalMs = 15_000): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      this.runScalingCycle().catch((err) => log.warn({ err }, '⚠️ Worker scaling cycle failed'));
    }, intervalMs);
    this.timer.unref?.();
  }

  /** Stops the periodic loop and releases the event-loop histogram. */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.loopMonitor?.disable();
  }

  getCurrentConcurrency(): number {
    return this.state.currentConcurrency;
  }

  getLastMetrics(): ScalingMetrics | null {
    return this.state.lastMetrics;
  }

  /** Forces concurrency for an operator override, still bounded. */
  forceScaleTo(workers: number): void {
    this.applyDecision({
      shouldScale: true,
      direction: workers >= this.state.currentConcurrency ? 'scale_up' : 'scale_down',
      recommendedWorkers: clamp(workers),
      reason: 'forced scale',
    });
  }
}

export default WorkerScaler;
