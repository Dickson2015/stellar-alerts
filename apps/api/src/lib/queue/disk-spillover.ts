/**
 * DiskSpilloverQueue: a local write-ahead journal for alert jobs that cannot
 * reach Redis.
 *
 * Each record is one line of length-prefixed NDJSON:
 *
 *   <payload byte length> <crc32 as 8 hex chars> <json payload>\n
 *
 * JSON.stringify escapes newlines, so a damaged record can never swallow the
 * next one: the reader resynchronises on the following newline.
 *
 * Writes are group-committed (one write + fsync per batch) and a caller is only
 * told a job is safe after that fsync. While any backlog exists new jobs join
 * the journal too, which keeps replay strictly FIFO. Replay reuses each job's
 * original ID, so BullMQ de-duplicates a job whose timed-out `add` eventually
 * landed after Redis came back.
 *
 * Processes sharing a directory each lock their own slot. A slot whose owner
 * has died is adopted and drained by a surviving process.
 */

import { randomBytes } from 'node:crypto';
import { promises as fs, type Dirent } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const SEGMENT_PREFIX = 'segment-';
const SEGMENT_SUFFIX = '.log';
const CHECKPOINT_SUFFIX = '.offset';
const LOCK_FILE = 'LOCK';
const QUARANTINE_FILE = 'quarantine.ndjson';
const CHECKPOINT_EVERY_RECORDS = 25;
const NEWLINE = 0x0a;

const CONNECTION_ERROR_CODES = new Set([
  'ECONNREFUSED',
  'ECONNRESET',
  'ECONNABORTED',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EPIPE',
  'ETIMEDOUT',
]);

const CONNECTION_ERROR_PATTERN =
  /connection is closed|connection lost|stream isn't writeable|max retries|reached the max|econnrefused|econnreset|etimedout|enotfound|epipe|^loading\b|^readonly\b|^clusterdown\b|^masterdown\b|^tryagain\b/i;

export interface SpilloverJob<T = unknown> {
  jobId: string;
  name: string;
  data: T;
  /** Priority lane the job was bound for, if any. */
  lane?: string;
  spilledAt?: string;
}

export type SpilloverEnqueueOutcome<R> =
  | { spilled: false; result: R }
  | { spilled: true; jobId: string };

export interface DiskSpilloverOptions<T, R> {
  /** Root directory; one `slot-N` subdirectory is used per process. */
  directory: string;
  /** Performs the real BullMQ enqueue. */
  sink: (job: SpilloverJob<T>) => Promise<R>;
  /** Resolves true once Redis can accept commands again. */
  isAvailable: () => Promise<boolean>;
  enqueueTimeoutMs?: number;
  drainIntervalMs?: number;
  maxSegmentBytes?: number;
  maxTotalBytes?: number;
  maxSlots?: number;
  lockStaleMs?: number;
  orphanSweepIntervalMs?: number;
  onError?: (message: string, err: unknown) => void;
}

export class SpilloverTimeoutError extends Error {
  readonly code = 'ETIMEDOUT';

  constructor(timeoutMs: number) {
    super(`Redis enqueue timed out after ${timeoutMs}ms`);
    this.name = 'SpilloverTimeoutError';
  }
}

export class SpilloverCapacityError extends Error {
  constructor(maxBytes: number) {
    super(`Spillover journal reached its ${maxBytes} byte limit`);
    this.name = 'SpilloverCapacityError';
  }
}

/** True for failures that mean "Redis is unreachable", not "this job is bad". */
export function isRedisConnectionError(err: unknown): boolean {
  if (err instanceof SpilloverTimeoutError) return true;
  if (typeof err !== 'object' || err === null) return false;
  const { code, message, name } = err as { code?: unknown; message?: unknown; name?: unknown };
  if (typeof code === 'string' && CONNECTION_ERROR_CODES.has(code)) return true;
  if (name === 'MaxRetriesPerRequestError') return true;
  return typeof message === 'string' && CONNECTION_ERROR_PATTERN.test(message);
}

// ── Record codec ────────────────────────────────────────────────────────────

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
})();

/** CRC-32 (IEEE 802.3). Implemented here because zlib.crc32 needs Node 22. */
export function crc32(buffer: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc = (CRC_TABLE[(crc ^ byte) & 0xff] as number) ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function encodeRecord(job: SpilloverJob<unknown>): Buffer {
  const payload = Buffer.from(JSON.stringify(job), 'utf8');
  const checksum = crc32(payload).toString(16).padStart(8, '0');
  return Buffer.concat([Buffer.from(`${payload.length} ${checksum} `, 'ascii'), payload, Buffer.from('\n')]);
}

export type DecodedRecord<T> =
  | { ok: true; job: SpilloverJob<T>; nextOffset: number }
  | { ok: false; reason: string; raw: Buffer; nextOffset: number };

/** Decodes the record at `offset`. Returns null at end of buffer. */
export function decodeRecord<T>(buffer: Buffer, offset: number): DecodedRecord<T> | null {
  if (offset >= buffer.length) return null;

  const newline = buffer.indexOf(NEWLINE, offset);
  if (newline === -1) {
    return { ok: false, reason: 'torn record', raw: buffer.subarray(offset), nextOffset: buffer.length };
  }

  const line = buffer.subarray(offset, newline);
  const nextOffset = newline + 1;
  const invalid = (reason: string): DecodedRecord<T> => ({ ok: false, reason, raw: line, nextOffset });

  const lengthEnd = line.indexOf(0x20);
  if (lengthEnd <= 0 || lengthEnd > 10) return invalid('malformed header');
  const checksumEnd = lengthEnd + 9;
  if (line[checksumEnd] !== 0x20) return invalid('malformed header');

  const lengthText = line.toString('ascii', 0, lengthEnd);
  const checksumText = line.toString('ascii', lengthEnd + 1, checksumEnd);
  if (!/^\d+$/.test(lengthText) || !/^[0-9a-f]{8}$/.test(checksumText)) return invalid('malformed header');

  const payload = line.subarray(checksumEnd + 1);
  if (payload.length !== Number(lengthText)) return invalid('length mismatch');
  if (crc32(payload) !== Number.parseInt(checksumText, 16)) return invalid('checksum mismatch');

  try {
    const job = JSON.parse(payload.toString('utf8')) as SpilloverJob<T>;
    if (typeof job?.jobId !== 'string' || typeof job.name !== 'string') return invalid('invalid job');
    return { ok: true, job, nextOffset };
  } catch {
    return invalid('invalid JSON');
  }
}

// ── Metrics ─────────────────────────────────────────────────────────────────

const activeQueues = new Set<{ bufferedJobs: number }>();

/** Slot directories locked by this process, whether owned or being adopted. */
const heldLocks = new Set<string>();

/** Prometheus exposition for the jobs currently waiting in this process's journal. */
export function renderSpilloverMetrics(): string {
  let buffered = 0;
  for (const queue of activeQueues) buffered += queue.bufferedJobs;
  return [
    '# HELP stellar_alerts_spillover_buffered_jobs Alert jobs buffered on disk awaiting Redis recovery',
    '# TYPE stellar_alerts_spillover_buffered_jobs gauge',
    `stellar_alerts_spillover_buffered_jobs ${buffered}`,
  ].join('\n');
}

// ── Queue ───────────────────────────────────────────────────────────────────

interface PendingAppend {
  line: Buffer;
  resolve: () => void;
  reject: (err: unknown) => void;
}

function segmentName(id: number): string {
  return `${SEGMENT_PREFIX}${String(id).padStart(16, '0')}${SEGMENT_SUFFIX}`;
}

function segmentId(name: string): number | null {
  if (!name.startsWith(SEGMENT_PREFIX) || !name.endsWith(SEGMENT_SUFFIX)) return null;
  const id = Number(name.slice(SEGMENT_PREFIX.length, -SEGMENT_SUFFIX.length));
  return Number.isSafeInteger(id) ? id : null;
}

async function fsyncDirectory(directory: string): Promise<void> {
  const handle = await fs.open(directory, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function errorCode(err: unknown): string | undefined {
  return (err as NodeJS.ErrnoException | undefined)?.code;
}

export class DiskSpilloverQueue<T = unknown, R = unknown> {
  bufferedJobs = 0;

  private readonly enqueueTimeoutMs: number;
  private readonly drainIntervalMs: number;
  private readonly maxSegmentBytes: number;
  private readonly maxTotalBytes: number;
  private readonly maxSlots: number;
  private readonly lockStaleMs: number;
  private readonly orphanSweepIntervalMs: number;

  private slotDirectory: string | null = null;
  private opening: Promise<void> | null = null;
  private closed = false;
  private spilling = false;

  private activeHandle: fs.FileHandle | null = null;
  private activeId = 0;
  private activeBytes = 0;
  private activeRecords = 0;
  private nextSegmentId = 1;
  private totalBytes = 0;

  private pending: PendingAppend[] = [];
  private flushScheduled = false;
  private mutex: Promise<unknown> = Promise.resolve();

  private draining: Promise<void> | null = null;
  private drainTimer: NodeJS.Timeout | null = null;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private orphanTimer: NodeJS.Timeout | null = null;
  private sweepingOrphans = false;

  constructor(private readonly options: DiskSpilloverOptions<T, R>) {
    this.enqueueTimeoutMs = options.enqueueTimeoutMs ?? 1_500;
    this.drainIntervalMs = options.drainIntervalMs ?? 1_000;
    this.maxSegmentBytes = options.maxSegmentBytes ?? 16 * 1024 * 1024;
    this.maxTotalBytes = options.maxTotalBytes ?? 1024 * 1024 * 1024;
    this.maxSlots = options.maxSlots ?? 16;
    this.lockStaleMs = options.lockStaleMs ?? 15_000;
    this.orphanSweepIntervalMs = options.orphanSweepIntervalMs ?? 30_000;
  }

  get isSpilling(): boolean {
    return this.spilling;
  }

  /** Locks a slot and recovers any backlog left by a previous process. */
  async open(): Promise<void> {
    if (this.closed) throw new Error('Spillover queue is closed');
    if (this.slotDirectory) return;
    this.opening ??= this.openSlot().finally(() => {
      this.opening = null;
    });
    await this.opening;
  }

  /**
   * Enqueues through the sink, journaling the job if Redis is unreachable.
   * Non-connection errors propagate. A journal failure also propagates, so the
   * caller can use its last-resort path instead of losing the alert.
   */
  async enqueue(job: SpilloverJob<T>): Promise<SpilloverEnqueueOutcome<R>> {
    if (this.spilling) return this.spill(job);

    try {
      return { spilled: false, result: await this.sinkWithTimeout(job) };
    } catch (err: unknown) {
      if (!isRedisConnectionError(err)) throw err;
      return this.spill(job);
    }
  }

  /** Replays the journal in FIFO order until it is empty or Redis fails again. */
  async drain(): Promise<void> {
    if (!this.slotDirectory) return;
    this.draining ??= this.runDrain().finally(() => {
      this.draining = null;
    });
    await this.draining;
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.stopTimer('drainTimer');
    this.stopTimer('orphanTimer');
    this.stopTimer('heartbeatTimer');
    if (this.opening) await this.opening.catch(() => undefined);
    if (this.draining) await this.draining.catch(() => undefined);

    await this.withMutex(async () => {
      await this.flushPending();
      await this.closeActive();
    });

    activeQueues.delete(this);
    if (this.slotDirectory) {
      await fs.rm(path.join(this.slotDirectory, LOCK_FILE), { force: true }).catch(() => undefined);
      heldLocks.delete(this.slotDirectory);
      this.slotDirectory = null;
    }
  }

  // ── Slot locking ──────────────────────────────────────────────────────────

  private async openSlot(): Promise<void> {
    await fs.mkdir(this.options.directory, { recursive: true });

    for (let slot = 0; slot < this.maxSlots; slot += 1) {
      const directory = path.join(this.options.directory, `slot-${slot}`);
      await fs.mkdir(directory, { recursive: true });
      if (await this.tryLock(directory)) {
        await this.adoptSlot(directory);
        return;
      }
    }
    throw new Error(`No free spillover slot in ${this.options.directory}`);
  }

  private async adoptSlot(directory: string): Promise<void> {
    this.slotDirectory = directory;
    activeQueues.add(this);
    this.heartbeatTimer = setInterval(() => {
      const now = new Date();
      fs.utimes(path.join(directory, LOCK_FILE), now, now).catch((err: unknown) => {
        this.report('Spillover lock heartbeat failed', err);
      });
    }, Math.max(Math.floor(this.lockStaleMs / 3), 10));
    this.heartbeatTimer.unref();

    await this.recover();
    this.orphanTimer = setInterval(() => void this.sweepOrphans(), this.orphanSweepIntervalMs);
    this.orphanTimer.unref();
    if (this.bufferedJobs > 0) {
      this.spilling = true;
      this.startDrainTimer();
    }
  }

  private async tryLock(directory: string): Promise<boolean> {
    const lockPath = path.join(directory, LOCK_FILE);

    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const handle = await fs.open(lockPath, 'wx');
        heldLocks.add(directory);
        try {
          await handle.writeFile(JSON.stringify({ host: os.hostname(), pid: process.pid }));
          await handle.sync();
        } finally {
          await handle.close();
        }
        return true;
      } catch (err: unknown) {
        if (errorCode(err) !== 'EEXIST') throw err;
      }

      if (!(await this.isLockStale(lockPath))) return false;

      // Rename is atomic, so only one contender can claim a stale lock.
      const claimed = `${lockPath}.stale-${randomBytes(4).toString('hex')}`;
      try {
        await fs.rename(lockPath, claimed);
      } catch (err: unknown) {
        if (errorCode(err) === 'ENOENT') continue;
        throw err;
      }
      if (!(await this.isLockStale(claimed))) {
        // Another process refreshed it between the check and the rename.
        await fs.link(claimed, lockPath).catch(() => undefined);
        await fs.rm(claimed, { force: true });
        return false;
      }
      await fs.rm(claimed, { force: true });
    }
    return false;
  }

  private async isLockStale(lockPath: string): Promise<boolean> {
    try {
      const [stat, content] = await Promise.all([fs.stat(lockPath), fs.readFile(lockPath, 'utf8')]);
      try {
        const owner = JSON.parse(content) as { host?: string; pid?: number };
        if (owner.host === os.hostname() && typeof owner.pid === 'number') {
          // This process holds no lock here yet, so its own PID means a previous
          // incarnation (common for PID 1 in a restarted container).
          if (owner.pid === process.pid) return !heldLocks.has(path.dirname(lockPath));
          try {
            process.kill(owner.pid, 0);
          } catch (err: unknown) {
            if (errorCode(err) === 'ESRCH') return true;
          }
        }
      } catch {
        // An unreadable owner falls through to the heartbeat age check.
      }
      return Date.now() - stat.mtimeMs > this.lockStaleMs;
    } catch (err: unknown) {
      if (errorCode(err) === 'ENOENT') return true;
      throw err;
    }
  }

  // ── Recovery ──────────────────────────────────────────────────────────────

  private async listSegments(): Promise<number[]> {
    const directory = this.slotDirectory as string;
    const entries: Dirent[] = await fs.readdir(directory, { withFileTypes: true });
    return entries
      .filter((entry) => entry.isFile())
      .map((entry) => segmentId(entry.name))
      .filter((id): id is number => id !== null)
      .sort((a, b) => a - b);
  }

  private segmentPath(id: number): string {
    return path.join(this.slotDirectory as string, segmentName(id));
  }

  private checkpointPath(id: number): string {
    return `${this.segmentPath(id)}${CHECKPOINT_SUFFIX}`;
  }

  private async readCheckpoint(id: number): Promise<number> {
    try {
      const value = Number((await fs.readFile(this.checkpointPath(id), 'utf8')).trim());
      return Number.isSafeInteger(value) && value > 0 ? value : 0;
    } catch (err: unknown) {
      if (errorCode(err) === 'ENOENT') return 0;
      throw err;
    }
  }

  private async writeCheckpoint(id: number, offset: number): Promise<void> {
    const target = this.checkpointPath(id);
    const temporary = `${target}.tmp`;
    const handle = await fs.open(temporary, 'w');
    try {
      await handle.writeFile(String(offset));
      await handle.sync();
    } finally {
      await handle.close();
    }
    await fs.rename(temporary, target);
  }

  private async recover(): Promise<void> {
    const directory = this.slotDirectory as string;
    const segments = await this.listSegments();
    const known = new Set(segments.map(segmentName));

    for (const entry of await fs.readdir(directory)) {
      const orphanCheckpoint =
        entry.endsWith(`${SEGMENT_SUFFIX}${CHECKPOINT_SUFFIX}`) && !known.has(entry.slice(0, -CHECKPOINT_SUFFIX.length));
      if (orphanCheckpoint || entry.endsWith(`${CHECKPOINT_SUFFIX}.tmp`)) {
        await fs.rm(path.join(directory, entry), { force: true });
      }
    }

    let buffered = 0;
    let bytes = 0;
    for (const id of segments) {
      const buffer = await fs.readFile(this.segmentPath(id));
      bytes += buffer.length;
      let offset = await this.readCheckpoint(id);
      for (;;) {
        const record = decodeRecord<T>(buffer, offset);
        if (!record) break;
        if (record.ok) buffered += 1;
        offset = record.nextOffset;
      }
    }

    this.bufferedJobs = buffered;
    this.totalBytes = bytes;
    // Old segments stay sealed so a torn tail is never appended to.
    this.nextSegmentId = (segments.at(-1) ?? 0) + 1;
  }

  // ── Append path ───────────────────────────────────────────────────────────

  private async spill(job: SpilloverJob<T>): Promise<SpilloverEnqueueOutcome<R>> {
    await this.open();
    const line = encodeRecord({ ...job, spilledAt: job.spilledAt ?? new Date().toISOString() });
    this.spilling = true;

    try {
      await new Promise<void>((resolve, reject) => {
        this.pending.push({ line, resolve, reject });
        this.scheduleFlush();
      });
    } catch (err: unknown) {
      if (this.bufferedJobs === 0 && this.pending.length === 0) this.spilling = false;
      throw err;
    }

    this.startDrainTimer();
    return { spilled: true, jobId: job.jobId };
  }

  private scheduleFlush(): void {
    if (this.flushScheduled) return;
    this.flushScheduled = true;
    void this.withMutex(async () => {
      this.flushScheduled = false;
      await this.flushPending();
    }).catch((err: unknown) => this.report('Spillover flush failed', err));
  }

  /** Group commit. Must run inside the mutex. */
  private async flushPending(): Promise<void> {
    while (this.pending.length > 0) {
      const batch = this.pending.splice(0);
      const data = Buffer.concat(batch.map((item) => item.line));

      try {
        if (this.totalBytes + data.length > this.maxTotalBytes) {
          throw new SpilloverCapacityError(this.maxTotalBytes);
        }
        if (this.activeHandle && this.activeBytes + data.length > this.maxSegmentBytes) {
          await this.closeActive();
        }
        const handle = await this.ensureActive();
        const startBytes = this.activeBytes;
        try {
          await handle.appendFile(data);
          await handle.sync();
        } catch (err: unknown) {
          // Drop any partial write so the segment ends on a record boundary.
          await handle.truncate(startBytes).catch(() => undefined);
          await this.closeActive();
          throw err;
        }

        this.activeBytes += data.length;
        this.activeRecords += batch.length;
        this.totalBytes += data.length;
        this.bufferedJobs += batch.length;
        for (const item of batch) item.resolve();
      } catch (err: unknown) {
        for (const item of batch) item.reject(err);
      }
    }
  }

  private async ensureActive(): Promise<fs.FileHandle> {
    if (this.activeHandle) return this.activeHandle;
    const id = this.nextSegmentId;
    const handle = await fs.open(this.segmentPath(id), 'a');
    await fsyncDirectory(this.slotDirectory as string);
    this.nextSegmentId += 1;
    this.activeHandle = handle;
    this.activeId = id;
    this.activeBytes = 0;
    this.activeRecords = 0;
    return handle;
  }

  private async closeActive(): Promise<void> {
    const handle = this.activeHandle;
    if (!handle) return;
    this.activeHandle = null;
    await handle.close();
    if (this.activeBytes === 0) await fs.rm(this.segmentPath(this.activeId), { force: true });
    this.activeBytes = 0;
    this.activeRecords = 0;
  }

  // ── Replay path ───────────────────────────────────────────────────────────

  private async runDrain(): Promise<void> {
    for (;;) {
      const next = await this.withMutex(async () => {
        if (this.pending.length > 0) await this.flushPending();
        await this.closeActive();
        const segments = await this.listSegments();
        if (segments.length === 0 && this.pending.length === 0) {
          // Flipped under the mutex so no acknowledged append can be stranded.
          this.spilling = false;
          this.bufferedJobs = 0;
          this.totalBytes = 0;
          this.stopTimer('drainTimer');
          return null;
        }
        return segments[0] ?? -1;
      });

      if (next === null) return;
      if (next !== -1) await this.replaySegment(next);
    }
  }

  private async replaySegment(id: number): Promise<void> {
    const buffer = await fs.readFile(this.segmentPath(id));
    const start = await this.readCheckpoint(id);
    let offset = start;
    let sinceCheckpoint = 0;

    try {
      for (;;) {
        const record = decodeRecord<T>(buffer, offset);
        if (!record) break;

        if (record.ok) {
          try {
            await this.sinkWithTimeout(record.job);
          } catch (err: unknown) {
            if (isRedisConnectionError(err)) throw err;
            // A job Redis rejects outright must not block everything behind it.
            this.report(`Quarantining spilled job ${record.job.jobId}`, err);
            await this.quarantine(`rejected: ${err instanceof Error ? err.message : String(err)}`, buffer.subarray(offset, record.nextOffset - 1));
          }
          this.bufferedJobs = Math.max(0, this.bufferedJobs - 1);
        } else {
          this.report(`Quarantining corrupt spillover record in segment ${id}`, new Error(record.reason));
          await this.quarantine(record.reason, record.raw);
        }

        offset = record.nextOffset;
        sinceCheckpoint += 1;
        if (sinceCheckpoint >= CHECKPOINT_EVERY_RECORDS) {
          await this.writeCheckpoint(id, offset);
          sinceCheckpoint = 0;
        }
      }
    } catch (err: unknown) {
      if (offset > start) await this.writeCheckpoint(id, offset);
      throw err;
    }

    await this.withMutex(async () => {
      await fs.rm(this.segmentPath(id), { force: true });
      await fs.rm(this.checkpointPath(id), { force: true });
      await fsyncDirectory(this.slotDirectory as string);
      this.totalBytes = Math.max(0, this.totalBytes - buffer.length);
    });
  }

  private async quarantine(reason: string, raw: Buffer): Promise<void> {
    const entry = JSON.stringify({ at: new Date().toISOString(), reason, record: raw.toString('base64') });
    const handle = await fs.open(path.join(this.slotDirectory as string, QUARANTINE_FILE), 'a');
    try {
      await handle.appendFile(`${entry}\n`);
      await handle.sync();
    } finally {
      await handle.close();
    }
  }

  // ── Background recovery ───────────────────────────────────────────────────

  private startDrainTimer(): void {
    if (this.drainTimer || this.closed) return;
    this.drainTimer = setInterval(() => void this.tick(), this.drainIntervalMs);
    this.drainTimer.unref();
  }

  private async tick(): Promise<void> {
    if (this.draining || this.closed) return;
    try {
      if (await this.options.isAvailable()) await this.drain();
    } catch (err: unknown) {
      if (!isRedisConnectionError(err)) this.report('Spillover drain failed', err);
    }
  }

  /** Drains slots whose owning process has died. */
  private async sweepOrphans(): Promise<void> {
    if (this.sweepingOrphans || this.closed || !this.slotDirectory) return;
    this.sweepingOrphans = true;
    try {
      if (!(await this.options.isAvailable())) return;
      const own = path.basename(this.slotDirectory);
      for (const entry of await fs.readdir(this.options.directory)) {
        if (entry === own || !entry.startsWith('slot-')) continue;
        const directory = path.join(this.options.directory, entry);
        if (heldLocks.has(directory)) continue;

        const hasSegments = (await fs.readdir(directory)).some((name) => segmentId(name) !== null);
        if (!hasSegments || !(await this.tryLock(directory))) continue;

        const adopter = new DiskSpilloverQueue<T, R>({ ...this.options, maxSlots: 0 });
        try {
          adopter.slotDirectory = directory;
          activeQueues.add(adopter);
          await adopter.recover();
          await adopter.drain();
        } finally {
          activeQueues.delete(adopter);
          adopter.slotDirectory = null;
          await fs.rm(path.join(directory, LOCK_FILE), { force: true });
          heldLocks.delete(directory);
        }
      }
    } catch (err: unknown) {
      if (!isRedisConnectionError(err)) this.report('Spillover orphan sweep failed', err);
    } finally {
      this.sweepingOrphans = false;
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  private sinkWithTimeout(job: SpilloverJob<T>): Promise<R> {
    return new Promise<R>((resolve, reject) => {
      const timer = setTimeout(() => reject(new SpilloverTimeoutError(this.enqueueTimeoutMs)), this.enqueueTimeoutMs);
      timer.unref();
      // With maxRetriesPerRequest: null an abandoned add stays in ioredis'
      // offline queue and may land later; its stable job ID makes that harmless.
      this.options.sink(job).then(
        (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        (err: unknown) => {
          clearTimeout(timer);
          reject(err);
        },
      );
    });
  }

  private withMutex<V>(task: () => Promise<V>): Promise<V> {
    const run = this.mutex.then(task, task);
    this.mutex = run.catch(() => undefined);
    return run;
  }

  private stopTimer(name: 'drainTimer' | 'heartbeatTimer' | 'orphanTimer'): void {
    const timer = this[name];
    if (timer) clearInterval(timer);
    this[name] = null;
  }

  private report(message: string, err: unknown): void {
    this.options.onError?.(message, err);
  }
}
