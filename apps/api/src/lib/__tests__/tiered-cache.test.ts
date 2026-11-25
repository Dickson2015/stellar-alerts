import { describe, expect, it, vi } from 'vitest';
import {
  SingleFlightTieredCache,
  type TieredCacheRedis,
  type TieredCacheSubscriber,
} from '../tiered-cache';

/** In-memory stand-in for Redis (store + pub/sub bus shared by several "nodes"). */
class FakeRedisBus {
  store = new Map<string, string>();
  private subs = new Set<{ channel: string; fn: (c: string, m: string) => void }>();
  failReads = false;

  client(): TieredCacheRedis {
    return {
      get: async (k) => {
        if (this.failReads) throw new Error('redis down');
        return this.store.get(k) ?? null;
      },
      set: async (k, v) => {
        this.store.set(k, v);
      },
      del: async (...keys) => {
        keys.forEach((k) => this.store.delete(k));
      },
      publish: async (channel, message) => {
        for (const s of this.subs) if (s.channel === channel) s.fn(channel, message);
      },
    };
  }

  subscriber(): TieredCacheSubscriber {
    let listener: ((c: string, m: string) => void) | null = null;
    let channel = '';
    const self = this;
    return {
      on: (_e, fn) => {
        listener = fn;
      },
      subscribe: async (c) => {
        channel = c;
        self.subs.add({ channel, fn: (ch, m) => listener?.(ch, m) });
      },
      unsubscribe: async () => {
        for (const s of self.subs) if (s.channel === channel) self.subs.delete(s);
      },
    };
  }
}

const deferred = <T>() => {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

const make = (bus = new FakeRedisBus(), over: Record<string, unknown> = {}) => {
  let now = 1_000_000;
  const cache = new SingleFlightTieredCache<string>({
    namespace: 'rules',
    redis: bus.client(),
    subscriber: bus.subscriber(),
    freshTtlMs: 1000,
    staleTtlMs: 5000,
    now: () => now,
    ...over,
  });
  return { cache, bus, advance: (ms: number) => (now += ms) };
};

describe('single-flight coalescing', () => {
  it('collapses N concurrent misses into exactly one loader call', async () => {
    const { cache } = make();
    const gate = deferred<string>();
    const loader = vi.fn(() => gate.promise);

    const calls = Array.from({ length: 50 }, () => cache.get('hot-wallet', loader));
    gate.resolve('rules-v1');

    expect(await Promise.all(calls)).toEqual(Array(50).fill('rules-v1'));
    expect(loader).toHaveBeenCalledTimes(1);
    expect(cache.stats().loads).toBe(1);
    expect(cache.stats().coalesced).toBe(49);
  });

  it('does not coalesce different keys', async () => {
    const { cache } = make();
    const loader = vi.fn(async () => 'x');
    await Promise.all([cache.get('a', loader), cache.get('b', loader)]);
    expect(loader).toHaveBeenCalledTimes(2);
  });

  it('shares a loader failure with every waiter and does not cache it', async () => {
    const { cache } = make();
    const gate = deferred<string>();
    const loader = vi.fn(() => gate.promise);
    const calls = [cache.get('k', loader), cache.get('k', loader), cache.get('k', loader)].map((p) =>
      p.catch((e: Error) => e.message),
    );
    gate.reject(new Error('db timeout'));
    expect(await Promise.all(calls)).toEqual(['db timeout', 'db timeout', 'db timeout']);
    expect(loader).toHaveBeenCalledTimes(1);

    // The failure is not sticky: the next call retries.
    await expect(cache.get('k', async () => 'ok')).resolves.toBe('ok');
  });
});

describe('tiering', () => {
  it('serves repeat reads from L1 without touching the loader', async () => {
    const { cache } = make();
    const loader = vi.fn(async () => 'v');
    await cache.get('k', loader);
    await cache.get('k', loader);
    expect(loader).toHaveBeenCalledTimes(1);
    expect(cache.stats().l1Hits).toBe(1);
  });

  it('a second node warms from L2 instead of the database', async () => {
    const bus = new FakeRedisBus();
    const a = make(bus).cache;
    const b = make(bus).cache;
    const loader = vi.fn(async () => 'shared');
    await a.get('k', loader);
    expect(await b.get('k', loader)).toBe('shared');
    expect(loader).toHaveBeenCalledTimes(1);
    expect(b.stats().l2Hits).toBe(1);
  });

  it('falls back to the loader when Redis reads fail', async () => {
    const bus = new FakeRedisBus();
    bus.failReads = true;
    const { cache } = make(bus);
    await expect(cache.get('k', async () => 'db')).resolves.toBe('db');
  });

  it('works without Redis at all (L1 only)', async () => {
    const cache = new SingleFlightTieredCache<string>({ namespace: 'n' });
    const loader = vi.fn(async () => 'v');
    await cache.get('k', loader);
    await cache.get('k', loader);
    expect(loader).toHaveBeenCalledTimes(1);
  });
});

describe('stale-while-revalidate', () => {
  it('serves the stale value immediately and refreshes in the background', async () => {
    const { cache, advance } = make();
    await cache.get('k', async () => 'v1');
    advance(1500); // past fresh (1s), inside stale window

    const gate = deferred<string>();
    const loader = vi.fn(() => gate.promise);
    expect(await cache.get('k', loader)).toBe('v1'); // not blocked on the loader
    expect(loader).toHaveBeenCalledTimes(1);

    gate.resolve('v2');
    await vi.waitFor(() => expect(cache.stats().loads).toBe(2));
    await new Promise((r) => setImmediate(r));
    expect(await cache.get('k', async () => 'unused')).toBe('v2');
    expect(cache.stats().staleServed).toBe(1);
  });

  it('many stale readers trigger a single refresh', async () => {
    const { cache, advance } = make();
    await cache.get('k', async () => 'v1');
    advance(1500);
    const gate = deferred<string>();
    const loader = vi.fn(() => gate.promise);
    const results = await Promise.all(Array.from({ length: 20 }, () => cache.get('k', loader)));
    expect(results).toEqual(Array(20).fill('v1'));
    expect(loader).toHaveBeenCalledTimes(1);
    gate.resolve('v2');
  });

  it('keeps serving stale when the background refresh fails', async () => {
    const { cache, advance } = make();
    await cache.get('k', async () => 'v1');
    advance(1500);
    await cache.get('k', async () => {
      throw new Error('db down');
    });
    await new Promise((r) => setImmediate(r));
    expect(await cache.get('k', async () => 'v3')).toBe('v1');
  });

  it('blocks on the loader once the stale window has also expired', async () => {
    const { cache, advance } = make();
    await cache.get('k', async () => 'v1');
    advance(10_000);
    expect(await cache.get('k', async () => 'v2')).toBe('v2');
  });
});

describe('cross-node invalidation', () => {
  it('evicts L1 on every other node when one node invalidates', async () => {
    const bus = new FakeRedisBus();
    const a = make(bus).cache;
    const b = make(bus).cache;
    await a.start();
    await b.start();

    await a.get('wallet-1', async () => 'old');
    await b.get('wallet-1', async () => 'old');

    await a.invalidate('wallet-1');

    const reload = vi.fn(async () => 'new');
    expect(await b.get('wallet-1', reload)).toBe('new');
    expect(reload).toHaveBeenCalledTimes(1);
    expect(b.stats().invalidationsReceived).toBe(1);
    expect(a.stats().invalidationsSent).toBe(1);
  });

  it('ignores its own broadcast', async () => {
    const bus = new FakeRedisBus();
    const a = make(bus, { nodeId: 'node-a' }).cache;
    await a.start();
    await a.invalidate('k');
    expect(a.stats().invalidationsReceived).toBe(0);
  });

  it('ignores malformed invalidation messages', async () => {
    const bus = new FakeRedisBus();
    const a = make(bus).cache;
    await a.start();
    await a.get('k', async () => 'v');
    await bus.client().publish('tiered-cache:invalidate:rules', 'not json');
    expect(await a.get('k', async () => 'other')).toBe('v');
  });

  it('a load racing an invalidation does not re-cache the stale result', async () => {
    const { cache } = make();
    const gate = deferred<string>();
    const racing = cache.get('k', () => gate.promise);
    await new Promise((r) => setImmediate(r));

    await cache.invalidate('k'); // rule updated while the old query is still running
    gate.resolve('stale-from-before-update');
    expect(await racing).toBe('stale-from-before-update'); // its own caller still gets an answer

    expect(await cache.get('k', async () => 'fresh-after-update')).toBe('fresh-after-update');
  });

  it('stops listening after close()', async () => {
    const bus = new FakeRedisBus();
    const a = make(bus).cache;
    const b = make(bus).cache;
    await b.start();
    await b.get('k', async () => 'v');
    await b.close();
    await a.invalidate('k');
    expect(b.stats().invalidationsReceived).toBe(0);
  });
});

describe('striped LRU', () => {
  it('evicts the least recently used entry when a stripe is full', async () => {
    const cache = new SingleFlightTieredCache<string>({ namespace: 'n', stripes: 1, l1MaxEntries: 2 });
    const loader = vi.fn(async (k: string) => k);
    await cache.get('a', () => loader('a'));
    await cache.get('b', () => loader('b'));
    await cache.get('a', () => loader('a')); // touch a, so b is now oldest
    await cache.get('c', () => loader('c')); // evicts b
    loader.mockClear();

    await cache.get('a', () => loader('a'));
    await cache.get('b', () => loader('b'));
    expect(loader).toHaveBeenCalledTimes(1);
    expect(loader).toHaveBeenCalledWith('b');
  });

  it('keeps total size bounded across stripes', async () => {
    const cache = new SingleFlightTieredCache<number>({ namespace: 'n', stripes: 8, l1MaxEntries: 80 });
    for (let i = 0; i < 1000; i++) await cache.get(`key-${i}`, async () => i);
    expect(cache.stats().l1Size).toBeLessThanOrEqual(80);
  });

  it('set() seeds both tiers', async () => {
    const { cache, bus } = make();
    await cache.set('k', 'seeded');
    expect(await cache.get('k', async () => 'loader')).toBe('seeded');
    expect(bus.store.has('tiered-cache:rules:k')).toBe(true);
  });
});
