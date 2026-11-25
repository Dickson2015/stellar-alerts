import { execFileSync, spawnSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Queue } from 'bullmq';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  DiskSpilloverQueue,
  crc32,
  decodeRecord,
  encodeRecord,
  isRedisConnectionError,
  renderSpilloverMetrics,
  type DiskSpilloverOptions,
  type SpilloverJob,
} from '../disk-spillover';

type Payload = { n: number };

const job = (n: number): SpilloverJob<Payload> => ({
  jobId: `payment-${n}`,
  name: 'dispatch-alert',
  data: { n },
  lane: 'standard',
});

function refused(): Error {
  return Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:6379'), { code: 'ECONNREFUSED' });
}

/** An in-memory BullMQ stand-in with an on/off switch and job-ID de-duplication. */
class FakeRedis {
  up = true;
  readonly jobs = new Map<string, SpilloverJob<Payload>>();

  sink = async (entry: SpilloverJob<Payload>): Promise<string> => {
    if (!this.up) throw refused();
    if (!this.jobs.has(entry.jobId)) this.jobs.set(entry.jobId, entry);
    return entry.jobId;
  };

  isAvailable = async (): Promise<boolean> => this.up;

  order(): number[] {
    return Array.from(this.jobs.values()).map((entry) => entry.data.n);
  }
}

describe('record codec', () => {
  it('computes the standard CRC-32 check value', () => {
    expect(crc32(Buffer.from('123456789'))).toBe(0xcbf43926);
  });

  it('round-trips a record, including embedded newlines and unicode', () => {
    const original: SpilloverJob<{ text: string }> = { jobId: 'a', name: 'n', data: { text: 'line1\nline2 ✓' } };
    const encoded = encodeRecord(original);
    expect(encoded.indexOf(0x0a)).toBe(encoded.length - 1);
    expect(decodeRecord(encoded, 0)).toMatchObject({ ok: true, job: original, nextOffset: encoded.length });
    expect(decodeRecord(encoded, encoded.length)).toBeNull();
  });

  it('detects a flipped payload byte and resynchronises on the next record', () => {
    const first = encodeRecord(job(1));
    const second = encodeRecord(job(2));
    first[first.length - 4] ^= 0x01;
    const buffer = Buffer.concat([first, second]);

    const damaged = decodeRecord<Payload>(buffer, 0);
    expect(damaged).toMatchObject({ ok: false, reason: 'checksum mismatch' });
    expect(decodeRecord<Payload>(buffer, damaged!.nextOffset)).toMatchObject({ ok: true, job: job(2) });
  });

  it('reports torn, short and malformed records', () => {
    const encoded = encodeRecord(job(1));
    expect(decodeRecord(encoded.subarray(0, encoded.length - 5), 0)).toMatchObject({ ok: false, reason: 'torn record' });
    expect(decodeRecord(Buffer.from('garbage\n'), 0)).toMatchObject({ ok: false, reason: 'malformed header' });
    const text = encoded.toString();
    expect(decodeRecord(Buffer.from(text.replace(/^\d+/, '1')), 0)).toMatchObject({ ok: false, reason: 'length mismatch' });
  });
});

describe('isRedisConnectionError', () => {
  it.each([
    refused(),
    Object.assign(new Error('x'), { code: 'ECONNRESET' }),
    new Error('Connection is closed.'),
    new Error("Stream isn't writeable and enableOfflineQueue options is false"),
    new Error('READONLY You cannot write against a read only replica.'),
    new Error('LOADING Redis is loading the dataset in memory'),
  ])('treats %s as a connection failure', (err) => {
    expect(isRedisConnectionError(err)).toBe(true);
  });

  it('does not treat application errors as connection failures', () => {
    expect(isRedisConnectionError(new Error('Custom Ids cannot contain :'))).toBe(false);
    expect(isRedisConnectionError(null)).toBe(false);
  });
});

describe('DiskSpilloverQueue', () => {
  let directory: string;
  const open: Array<DiskSpilloverQueue<Payload, string>> = [];

  const create = (redis: FakeRedis, overrides: Partial<DiskSpilloverOptions<Payload, string>> = {}) => {
    const queue = new DiskSpilloverQueue<Payload, string>({
      directory,
      sink: redis.sink,
      isAvailable: redis.isAvailable,
      drainIntervalMs: 5,
      enqueueTimeoutMs: 100,
      lockStaleMs: 60_000,
      ...overrides,
    });
    open.push(queue);
    return queue;
  };

  const segments = async (slot = 0) => {
    const names = await fs.readdir(path.join(directory, `slot-${slot}`));
    return names.filter((name) => name.startsWith('segment-')).sort();
  };

  beforeEach(async () => {
    directory = await fs.mkdtemp(path.join(os.tmpdir(), 'spillover-'));
  });

  afterEach(async () => {
    await Promise.all(open.splice(0).map((queue) => queue.close()));
    await fs.rm(directory, { recursive: true, force: true });
  });

  it('passes through without touching disk while Redis is healthy', async () => {
    const redis = new FakeRedis();
    const queue = create(redis);
    await expect(queue.enqueue(job(1))).resolves.toEqual({ spilled: false, result: 'payment-1' });
    await expect(fs.readdir(directory)).resolves.toEqual([]);
  });

  it('rethrows non-connection errors instead of journaling them', async () => {
    const queue = create(new FakeRedis(), { sink: async () => Promise.reject(new Error('invalid job')) });
    await expect(queue.enqueue(job(1))).rejects.toThrow('invalid job');
    expect(queue.bufferedJobs).toBe(0);
  });

  it('spills when an add hangs, as ioredis does with maxRetriesPerRequest: null', async () => {
    const queue = create(new FakeRedis(), {
      sink: () => new Promise<string>(() => undefined),
      isAvailable: async () => false,
      enqueueTimeoutMs: 10,
    });
    await expect(queue.enqueue(job(1))).resolves.toEqual({ spilled: true, jobId: 'payment-1' });
    expect(queue.bufferedJobs).toBe(1);
  });

  it('replays 500 jobs in FIFO order with original IDs, then removes its segments', async () => {
    const redis = new FakeRedis();
    const queue = create(redis);
    redis.up = false;

    const outcomes = await Promise.all(Array.from({ length: 500 }, (_, n) => queue.enqueue(job(n))));
    expect(outcomes.every((outcome) => outcome.spilled)).toBe(true);
    expect(queue.bufferedJobs).toBe(500);
    expect(renderSpilloverMetrics()).toContain('stellar_alerts_spillover_buffered_jobs 500');

    redis.up = true;
    await vi.waitFor(() => expect(queue.isSpilling).toBe(false), { timeout: 5_000 });

    expect(redis.order()).toEqual(Array.from({ length: 500 }, (_, n) => n));
    expect(redis.jobs.get('payment-42')?.lane).toBe('standard');
    expect(queue.bufferedJobs).toBe(0);
    expect(await segments()).toEqual([]);
    expect(renderSpilloverMetrics()).toContain('stellar_alerts_spillover_buffered_jobs 0');
  });

  it('keeps FIFO order when new jobs arrive during replay', async () => {
    const redis = new FakeRedis();
    let injected = false;
    const queue: DiskSpilloverQueue<Payload, string> = create(redis, {
      sink: async (entry) => {
        const result = await redis.sink(entry);
        if (entry.data.n === 5 && !injected) {
          injected = true;
          await queue.enqueue(job(100));
        }
        return result;
      },
    });
    redis.up = false;
    for (let n = 0; n < 10; n += 1) await queue.enqueue(job(n));
    redis.up = true;

    await vi.waitFor(() => expect(queue.isSpilling).toBe(false), { timeout: 5_000 });
    expect(redis.order()).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 100]);
  });

  it('resumes after Redis fails again mid-replay without losing or duplicating jobs', async () => {
    const redis = new FakeRedis();
    const delivered: number[] = [];
    let failed = false;
    const queue = create(redis, {
      sink: async (entry) => {
        if (entry.data.n === 30 && !failed) {
          failed = true;
          redis.up = false;
          setTimeout(() => {
            redis.up = true;
          }, 30);
        }
        const result = await redis.sink(entry);
        delivered.push(entry.data.n);
        return result;
      },
    });
    redis.up = false;
    for (let n = 0; n < 60; n += 1) await queue.enqueue(job(n));
    redis.up = true;

    await vi.waitFor(() => expect(queue.isSpilling).toBe(false), { timeout: 5_000 });
    expect(redis.order()).toEqual(Array.from({ length: 60 }, (_, n) => n));
    expect(failed).toBe(true);
  });

  it('recovers a journal after a crash, ignoring a torn final record', async () => {
    const redis = new FakeRedis();
    redis.up = false;
    const slot = path.join(directory, 'slot-0');
    await fs.mkdir(slot, { recursive: true });
    const complete = Buffer.concat([encodeRecord(job(1)), encodeRecord(job(2))]);
    const torn = encodeRecord(job(3)).subarray(0, 12);
    await fs.writeFile(path.join(slot, 'segment-0000000000000001.log'), Buffer.concat([complete, torn]));

    const queue = create(redis);
    await queue.open();
    expect(queue.bufferedJobs).toBe(2);

    redis.up = true;
    await vi.waitFor(() => expect(queue.isSpilling).toBe(false), { timeout: 5_000 });
    expect(redis.order()).toEqual([1, 2]);
    expect(await fs.readFile(path.join(slot, 'quarantine.ndjson'), 'utf8')).toContain('torn record');
  });

  it('quarantines corrupt records and still replays the rest', async () => {
    const redis = new FakeRedis();
    redis.up = false;
    const slot = path.join(directory, 'slot-0');
    await fs.mkdir(slot, { recursive: true });
    const bad = encodeRecord(job(2));
    bad[bad.length - 3] ^= 0xff;
    await fs.writeFile(
      path.join(slot, 'segment-0000000000000001.log'),
      Buffer.concat([encodeRecord(job(1)), bad, encodeRecord(job(3))]),
    );

    const queue = create(redis);
    await queue.open();
    redis.up = true;
    await vi.waitFor(() => expect(queue.isSpilling).toBe(false), { timeout: 5_000 });
    expect(redis.order()).toEqual([1, 3]);
  });

  it('resumes from the replay checkpoint', async () => {
    const redis = new FakeRedis();
    redis.up = false;
    const slot = path.join(directory, 'slot-0');
    await fs.mkdir(slot, { recursive: true });
    const first = encodeRecord(job(1));
    const name = 'segment-0000000000000001.log';
    await fs.writeFile(path.join(slot, name), Buffer.concat([first, encodeRecord(job(2))]));
    await fs.writeFile(path.join(slot, `${name}.offset`), String(first.length));

    const queue = create(redis);
    await queue.open();
    expect(queue.bufferedJobs).toBe(1);
    redis.up = true;
    await vi.waitFor(() => expect(queue.isSpilling).toBe(false), { timeout: 5_000 });
    expect(redis.order()).toEqual([2]);
  });

  it('rotates segments at the size limit and replays across them in order', async () => {
    const redis = new FakeRedis();
    const queue = create(redis, { maxSegmentBytes: 256 });
    redis.up = false;
    for (let n = 0; n < 40; n += 1) await queue.enqueue(job(n));
    expect((await segments()).length).toBeGreaterThan(1);

    redis.up = true;
    await vi.waitFor(() => expect(queue.isSpilling).toBe(false), { timeout: 5_000 });
    expect(redis.order()).toEqual(Array.from({ length: 40 }, (_, n) => n));
    expect(await segments()).toEqual([]);
  });

  it('rejects when the journal is full so the caller can use its fallback', async () => {
    const redis = new FakeRedis();
    const queue = create(redis, { maxTotalBytes: 32 });
    redis.up = false;
    await expect(queue.enqueue(job(1))).rejects.toThrow(/byte limit/);
  });

  it('gives concurrent processes separate slots', async () => {
    const redis = new FakeRedis();
    redis.up = false;
    const first = create(redis);
    const second = create(redis);
    await first.enqueue(job(1));
    await second.enqueue(job(2));
    expect(await segments(0)).toHaveLength(1);
    expect(await segments(1)).toHaveLength(1);
  });

  it('adopts and drains a slot whose owner has died', async () => {
    const redis = new FakeRedis();
    redis.up = false;
    const orphan = path.join(directory, 'slot-1');
    await fs.mkdir(orphan, { recursive: true });
    await fs.writeFile(path.join(orphan, 'segment-0000000000000001.log'), encodeRecord(job(7)));
    const dead = spawnSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], { encoding: 'utf8' });
    await fs.writeFile(path.join(orphan, 'LOCK'), JSON.stringify({ host: os.hostname(), pid: Number(dead.stdout) }));

    const queue = create(redis, { orphanSweepIntervalMs: 10 });
    await queue.open();
    redis.up = true;

    await vi.waitFor(() => expect(redis.order()).toEqual([7]), { timeout: 5_000 });
    await vi.waitFor(async () => expect(await segments(1)).toEqual([]), { timeout: 5_000 });
  });
});

/**
 * Exercises real BullMQ against a disposable Redis container. Set
 * SPILLOVER_TEST_REDIS_CONTAINER to a running container published on
 * SPILLOVER_TEST_REDIS_PORT; the test stops and restarts that container.
 */
const container = process.env.SPILLOVER_TEST_REDIS_CONTAINER;
const port = Number(process.env.SPILLOVER_TEST_REDIS_PORT ?? 0);

describe.skipIf(!container || !port)('DiskSpilloverQueue with a real Redis outage', () => {
  it('replays all 500 jobs enqueued while Redis is down', { timeout: 120_000 }, async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'spillover-real-'));
    const connection = {
      host: '127.0.0.1',
      port,
      maxRetriesPerRequest: null,
      retryStrategy: (times: number) => Math.min(times * 100, 500),
    };
    const queueName = `spillover-it-${process.pid}`;
    const queue = new Queue<Payload>(queueName, { connection });
    queue.on('error', () => undefined);
    await queue.waitUntilReady();

    const spillover = new DiskSpilloverQueue<Payload, unknown>({
      directory,
      enqueueTimeoutMs: 200,
      drainIntervalMs: 100,
      sink: (entry) => queue.add(entry.name, entry.data, { jobId: entry.jobId }),
      isAvailable: async () => {
        const client = (await queue.client) as unknown as { status: string; ping(): Promise<string> };
        return client.status === 'ready' && (await client.ping()) === 'PONG';
      },
    });

    try {
      execFileSync('docker', ['stop', '-t', '0', container as string]);

      // Sequential-first so the outage is detected, then the rest concurrently.
      const first = await spillover.enqueue(job(0));
      expect(first.spilled).toBe(true);
      const rest = await Promise.all(Array.from({ length: 499 }, (_, n) => spillover.enqueue(job(n + 1))));
      expect(rest.every((outcome) => outcome.spilled)).toBe(true);
      expect(spillover.bufferedJobs).toBe(500);

      execFileSync('docker', ['start', container as string]);
      await vi.waitFor(() => expect(spillover.isSpilling).toBe(false), { timeout: 60_000, interval: 100 });

      const stored = await queue.getJobs(['waiting'], 0, 1000, true);
      expect(stored).toHaveLength(500);
      expect(new Set(stored.map((entry) => entry.id)).size).toBe(500);
      expect(stored.map((entry) => entry.data.n)).toEqual(Array.from({ length: 500 }, (_, n) => n));
      expect(spillover.bufferedJobs).toBe(0);
    } finally {
      await spillover.close();
      await queue.obliterate({ force: true }).catch(() => undefined);
      await queue.close();
      await fs.rm(directory, { recursive: true, force: true });
    }
  });
});
