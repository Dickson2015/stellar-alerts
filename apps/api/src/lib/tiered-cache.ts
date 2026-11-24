/**
 * Two-level cache with stampede protection (#989).
 *
 *   L1  striped in-process LRU        (sub-millisecond, per worker)
 *   L2  Redis                          (shared across workers)
 *   --  single-flight coalescing       (N concurrent misses -> 1 loader call)
 *   --  stale-while-revalidate         (serve old value, refresh in background)
 *   --  Redis pub/sub invalidation     (writes on one node evict L1 everywhere)
 *
 * Node's event loop makes every Map operation atomic, so the structure needs
 * no locks; "striping" splits the LRU into independent shards so eviction
 * bookkeeping and hot-key churn never touch the whole keyspace.
 */

import { createLogger } from './logger';

const log = createLogger({ module: 'SingleFlightTieredCache' });

/** Upper bound on remembered invalidation generations (keeps memory flat). */
const MAX_TRACKED_GENERATIONS = 10_000;

/** The slice of ioredis this cache needs. */
export interface TieredCacheRedis {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode: 'EX', seconds: number): Promise<unknown>;
  del(...keys: string[]): Promise<unknown>;
  publish(channel: string, message: string): Promise<unknown>;
}

/** A dedicated connection in subscriber mode (ioredis `duplicate()`). */
export interface TieredCacheSubscriber {
  subscribe(channel: string): Promise<unknown>;
  unsubscribe(channel: string): Promise<unknown>;
  on(event: 'message', listener: (channel: string, message: string) => void): unknown;
  off?(event: 'message', listener: (channel: string, message: string) => void): unknown;
  removeListener?(event: 'message', listener: (channel: string, message: string) => void): unknown;
}

export interface TieredCacheOptions {
  /** Namespaces Redis keys and the invalidation channel, e.g. "wallet-rules". */
  namespace: string;
  redis?: TieredCacheRedis | null;
  subscriber?: TieredCacheSubscriber | null;
  /** Max entries held in L1 across all stripes. Default 5000. */
  l1MaxEntries?: number;
  /** Number of independent LRU stripes. Default 16. */
  stripes?: number;
  /** How long a value is served as fresh. Default 30s. */
  freshTtlMs?: number;
  /** Extra window after `freshTtlMs` in which stale values are served while refreshing. Default 5min. */
  staleTtlMs?: number;
  /** Unique id of this process, so it ignores its own invalidation broadcasts. */
  nodeId?: string;
  now?: () => number;
}

export interface TieredCacheStats {
  l1Hits: number;
  l2Hits: number;
  misses: number;
  /** Callers that piggy-backed on an already-running load. */
  coalesced: number;
  /** Loader invocations (each is one underlying database query). */
  loads: number;
  staleServed: number;
  backgroundRefreshes: number;
  loadErrors: number;
  invalidationsSent: number;
  invalidationsReceived: number;
  l1Size: number;
}

interface Entry<T> {
  value: T;
  freshUntil: number;
  staleUntil: number;
}

/** Wire format stored in Redis. */
interface Envelope<T> {
  v: T;
  f: number;
  s: number;
}

interface InvalidationMessage {
  key: string;
  origin: string;
}

class LruStripe<T> {
  private readonly map = new Map<string, Entry<T>>();
  constructor(private readonly capacity: number) {}

  get(key: string): Entry<T> | undefined {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    // Re-insert to mark as most recently used.
    this.map.delete(key);
    this.map.set(key, entry);
    return entry;
  }

  set(key: string, entry: Entry<T>): void {
    this.map.delete(key);
    this.map.set(key, entry);
    while (this.map.size > this.capacity) {
      const oldest = this.map.keys().next().value as string;
      this.map.delete(oldest);
    }
  }

  delete(key: string): void {
    this.map.delete(key);
  }

  clear(): void {
    this.map.clear();
  }

  get size(): number {
    return this.map.size;
  }
}

/** FNV-1a, stable and cheap; only used to pick a stripe. */
function stripeIndex(key: string, stripes: number): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < key.length; i++) {
    hash ^= key.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0) % stripes;
}

export class SingleFlightTieredCache<T> {
  private readonly namespace: string;
  private readonly redis: TieredCacheRedis | null;
  private readonly subscriber: TieredCacheSubscriber | null;
  private readonly stripes: LruStripe<T>[];
  private readonly freshTtlMs: number;
  private readonly staleTtlMs: number;
  private readonly nodeId: string;
  private readonly now: () => number;
  private readonly channel: string;

  /** One in-flight load per key; every concurrent caller awaits the same promise. */
  private readonly inflight = new Map<string, Promise<T>>();
  /** Bumped on invalidation so an older, slower load cannot re-cache stale data. */
  private readonly generations = new Map<string, number>();
  private listener: ((channel: string, message: string) => void) | null = null;

  private counters = {
    l1Hits: 0,
    l2Hits: 0,
    misses: 0,
    coalesced: 0,
    loads: 0,
    staleServed: 0,
    backgroundRefreshes: 0,
    loadErrors: 0,
    invalidationsSent: 0,
    invalidationsReceived: 0,
  };

  constructor(options: TieredCacheOptions) {
    this.namespace = options.namespace;
    this.redis = options.redis ?? null;
    this.subscriber = options.subscriber ?? null;
    this.freshTtlMs = options.freshTtlMs ?? 30_000;
    this.staleTtlMs = options.staleTtlMs ?? 5 * 60_000;
    this.nodeId = options.nodeId ?? `${process.pid}-${Math.random().toString(36).slice(2, 10)}`;
    this.now = options.now ?? Date.now;
    this.channel = `tiered-cache:invalidate:${this.namespace}`;

    const stripeCount = Math.max(1, options.stripes ?? 16);
    const perStripe = Math.max(1, Math.ceil((options.l1MaxEntries ?? 5000) / stripeCount));
    this.stripes = Array.from({ length: stripeCount }, () => new LruStripe<T>(perStripe));
  }

  /** Subscribes to cross-node invalidations. Safe to skip in single-node setups. */
  async start(): Promise<void> {
    if (!this.subscriber || this.listener) return;
    this.listener = (channel, message) => {
      if (channel !== this.channel) return;
      let parsed: InvalidationMessage;
      try {
        parsed = JSON.parse(message) as InvalidationMessage;
      } catch {
        return;
      }
      if (parsed.origin === this.nodeId || typeof parsed.key !== 'string') return;
      this.counters.invalidationsReceived++;
      this.evictLocal(parsed.key);
    };
    this.subscriber.on('message', this.listener);
    await this.subscriber.subscribe(this.channel);
  }

  async close(): Promise<void> {
    if (this.subscriber && this.listener) {
      const remove = this.subscriber.off ?? this.subscriber.removeListener;
      remove?.call(this.subscriber, 'message', this.listener);
      await this.subscriber.unsubscribe(this.channel).catch(() => undefined);
    }
    this.listener = null;
    this.stripes.forEach((s) => s.clear());
    this.inflight.clear();
  }

  /**
   * Returns the cached value for `key`, calling `loader` only when no usable
   * copy exists. Concurrent callers for the same key share one loader call.
   */
  async get(key: string, loader: () => Promise<T>): Promise<T> {
    const now = this.now();
    const stripe = this.stripeFor(key);

    const local = stripe.get(key);
    if (local && now < local.freshUntil) {
      this.counters.l1Hits++;
      return local.value;
    }
    if (local && now < local.staleUntil) {
      this.counters.staleServed++;
      this.refreshInBackground(key, loader);
      return local.value;
    }

    // L1 miss: a load may already be running; join it instead of starting another.
    const running = this.inflight.get(key);
    if (running) {
      this.counters.coalesced++;
      return running;
    }

    const promise = this.loadThroughL2(key, loader).finally(() => {
      if (this.inflight.get(key) === promise) this.inflight.delete(key);
    });
    this.inflight.set(key, promise);
    return promise;
  }

  /** Drops the key in Redis and locally, then tells every other node to do the same. */
  async invalidate(key: string): Promise<void> {
    // Clear L2 first so a load that starts right after the local eviction
    // cannot repopulate L1 from the old Redis copy.
    let redisOk = true;
    if (this.redis) {
      try {
        await this.redis.del(this.redisKey(key));
      } catch (err) {
        redisOk = false;
        log.warn({ key, err: errMessage(err) }, 'L2 invalidation failed');
      }
    }
    this.evictLocal(key);
    if (!this.redis || !redisOk) return;
    try {
      const message: InvalidationMessage = { key, origin: this.nodeId };
      await this.redis.publish(this.channel, JSON.stringify(message));
      this.counters.invalidationsSent++;
    } catch (err) {
      log.warn({ key, err: errMessage(err) }, 'Cache invalidation broadcast failed');
    }
  }

  /** Seeds both tiers with a freshly written value (e.g. right after a DB update). */
  async set(key: string, value: T): Promise<void> {
    await this.store(key, value, this.generation(key));
  }

  stats(): TieredCacheStats {
    return { ...this.counters, l1Size: this.stripes.reduce((n, s) => n + s.size, 0) };
  }

  // ── internals ───────────────────────────────────────────────────────────

  private async loadThroughL2(key: string, loader: () => Promise<T>): Promise<T> {
    const generation = this.generation(key);

    const fromL2 = await this.readL2(key);
    if (fromL2) {
      const now = this.now();
      if (now < fromL2.staleUntil) {
        this.stripeFor(key).set(key, fromL2);
        if (now < fromL2.freshUntil) {
          this.counters.l2Hits++;
          return fromL2.value;
        }
        this.counters.staleServed++;
        this.refreshInBackground(key, loader);
        return fromL2.value;
      }
    }

    this.counters.misses++;
    return this.runLoader(key, loader, generation);
  }

  private async runLoader(key: string, loader: () => Promise<T>, generation: number): Promise<T> {
    this.counters.loads++;
    try {
      const value = await loader();
      await this.store(key, value, generation);
      return value;
    } catch (err) {
      this.counters.loadErrors++;
      throw err;
    }
  }

  /** Refreshes without blocking the caller; errors keep the stale value alive. */
  private refreshInBackground(key: string, loader: () => Promise<T>): void {
    if (this.inflight.has(key)) return;
    this.counters.backgroundRefreshes++;
    const generation = this.generation(key);
    const promise = this.runLoader(key, loader, generation).finally(() => {
      if (this.inflight.get(key) === promise) this.inflight.delete(key);
    });
    this.inflight.set(key, promise);
    promise.catch((err) => {
      log.warn({ key, err: errMessage(err) }, 'Background cache refresh failed; serving stale value');
    });
  }

  private async store(key: string, value: T, generation: number): Promise<void> {
    // The key was invalidated while this load was running: its result may
    // predate the change, so drop it instead of re-caching stale data.
    if (generation !== this.generation(key)) return;

    const now = this.now();
    const entry: Entry<T> = {
      value,
      freshUntil: now + this.freshTtlMs,
      staleUntil: now + this.freshTtlMs + this.staleTtlMs,
    };
    this.stripeFor(key).set(key, entry);

    if (!this.redis) return;
    try {
      const envelope: Envelope<T> = { v: value, f: entry.freshUntil, s: entry.staleUntil };
      const ttlSeconds = Math.max(1, Math.ceil((this.freshTtlMs + this.staleTtlMs) / 1000));
      await this.redis.set(this.redisKey(key), JSON.stringify(envelope), 'EX', ttlSeconds);
    } catch (err) {
      log.warn({ key, err: errMessage(err) }, 'L2 cache write failed; L1 still populated');
    }
  }

  private async readL2(key: string): Promise<Entry<T> | null> {
    if (!this.redis) return null;
    try {
      const raw = await this.redis.get(this.redisKey(key));
      if (!raw) return null;
      const envelope = JSON.parse(raw) as Envelope<T>;
      return { value: envelope.v, freshUntil: envelope.f, staleUntil: envelope.s };
    } catch (err) {
      log.warn({ key, err: errMessage(err) }, 'L2 cache read failed; falling back to loader');
      return null;
    }
  }

  private evictLocal(key: string): void {
    const next = this.generation(key) + 1;
    // Delete + set moves the key to the newest position so trimming drops the oldest.
    this.generations.delete(key);
    this.generations.set(key, next);
    if (this.generations.size > MAX_TRACKED_GENERATIONS) {
      this.generations.delete(this.generations.keys().next().value as string);
    }
    this.stripeFor(key).delete(key);
    // Let any running load finish for its own callers, but a new get() must start fresh.
    this.inflight.delete(key);
  }

  private generation(key: string): number {
    return this.generations.get(key) ?? 0;
  }

  private stripeFor(key: string): LruStripe<T> {
    return this.stripes[stripeIndex(key, this.stripes.length)];
  }

  private redisKey(key: string): string {
    return `tiered-cache:${this.namespace}:${key}`;
  }
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
