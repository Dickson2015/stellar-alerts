import { prisma } from '../../lib/prisma';

export const TIME_SERIES_INTERVALS = {
  '1m': 60_000,
  '5m': 5 * 60_000,
  '1h': 60 * 60_000,
} as const;

export type TimeSeriesInterval = keyof typeof TIME_SERIES_INTERVALS;

export interface PaymentTelemetryEvent {
  amount: number | string;
  asset: string;
  assetIssuer?: string | null;
  fromAddress: string;
  receivedAt: Date | number;
}

export interface TimeSeriesBucket {
  asset: string;
  interval: TimeSeriesInterval;
  bucketStart: Date;
  count: number;
  volume: number;
  minAmount: number;
  maxAmount: number;
  uniqueSenders: number;
}

interface PendingBucket extends Omit<TimeSeriesBucket, 'bucketStart' | 'uniqueSenders'> {
  bucketStart: number;
  senders: Set<string>;
}

export interface TimeSeriesRollupStore {
  upsert(bucket: PendingBucket): Promise<void>;
  query(options: {
    asset?: string;
    interval: TimeSeriesInterval;
    from: Date;
    to: Date;
    limit: number;
  }): Promise<TimeSeriesBucket[]>;
}

/**
 * Persists rollups in the TimeSeriesRollup table. The corresponding Prisma
 * model/migration is intentionally maintained with the shared schema.
 */
class PrismaTimeSeriesRollupStore implements TimeSeriesRollupStore {
  async upsert(bucket: PendingBucket): Promise<void> {
    await prisma.$executeRawUnsafe(
      `INSERT INTO "TimeSeriesRollup"
        ("asset", "interval", "bucketStart", "count", "volume", "minAmount", "maxAmount", "uniqueSenders", "updatedAt")
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text[], NOW())
       ON CONFLICT ("asset", "interval", "bucketStart") DO UPDATE SET
         "count" = "TimeSeriesRollup"."count" + EXCLUDED."count",
         "volume" = "TimeSeriesRollup"."volume" + EXCLUDED."volume",
         "minAmount" = LEAST("TimeSeriesRollup"."minAmount", EXCLUDED."minAmount"),
         "maxAmount" = GREATEST("TimeSeriesRollup"."maxAmount", EXCLUDED."maxAmount"),
         "uniqueSenders" = ARRAY(
           SELECT DISTINCT sender
           FROM unnest("TimeSeriesRollup"."uniqueSenders" || EXCLUDED."uniqueSenders") AS senders(sender)
         ),
         "updatedAt" = NOW()`,
      bucket.asset,
      bucket.interval,
      new Date(bucket.bucketStart),
      bucket.count,
      bucket.volume,
      bucket.minAmount,
      bucket.maxAmount,
      [...bucket.senders],
    );
  }

  async query(options: {
    asset?: string;
    interval: TimeSeriesInterval;
    from: Date;
    to: Date;
    limit: number;
  }): Promise<TimeSeriesBucket[]> {
    const rows = await prisma.$queryRawUnsafe<Array<{
      asset: string;
      interval: TimeSeriesInterval;
      bucketStart: Date;
      count: number | bigint;
      volume: number | string;
      minAmount: number | string;
      maxAmount: number | string;
      uniqueSenders: string[];
    }>>(
      `SELECT "asset", "interval", "bucketStart", "count", "volume",
              "minAmount", "maxAmount", cardinality("uniqueSenders") AS "uniqueSenders"
       FROM "TimeSeriesRollup"
       WHERE "interval" = $1 AND "bucketStart" >= $2 AND "bucketStart" < $3
         AND ($4::text IS NULL OR "asset" = $4)
       ORDER BY "bucketStart" ASC
       LIMIT $5`,
      options.interval,
      options.from,
      options.to,
      options.asset ?? null,
      options.limit,
    );
    return rows.map((row) => ({
      ...row,
      bucketStart: new Date(row.bucketStart),
      count: Number(row.count),
      volume: Number(row.volume),
      minAmount: Number(row.minAmount),
      maxAmount: Number(row.maxAmount),
      uniqueSenders: Number(row.uniqueSenders),
    }));
  }
}

function mergePending(target: PendingBucket, incoming: PendingBucket): void {
  target.count += incoming.count;
  target.volume += incoming.volume;
  target.minAmount = Math.min(target.minAmount, incoming.minAmount);
  target.maxAmount = Math.max(target.maxAmount, incoming.maxAmount);
  for (const sender of incoming.senders) target.senders.add(sender);
}

function bucketKey(asset: string, interval: TimeSeriesInterval, start: number): string {
  return `${asset}\u0000${interval}\u0000${start}`;
}

export class TimeSeriesRollupEngine {
  private readonly store: TimeSeriesRollupStore;
  private readonly pending = new Map<string, PendingBucket>();
  private flushPromise: Promise<void> | null = null;

  constructor(store: TimeSeriesRollupStore = new PrismaTimeSeriesRollupStore()) {
    this.store = store;
  }

  /** Adds one newly-ingested payment to all supported tumbling windows. */
  record(event: PaymentTelemetryEvent): void {
    const amount = Number(event.amount);
    const timestamp = event.receivedAt instanceof Date ? event.receivedAt.getTime() : event.receivedAt;
    if (!Number.isFinite(amount) || amount < 0) throw new Error('Payment amount must be a finite non-negative number');
    if (!Number.isFinite(timestamp)) throw new Error('Payment timestamp must be finite');
    if (!event.asset.trim()) throw new Error('Payment asset must not be empty');

    // Include the issuer to keep identically named Stellar assets distinct.
    const asset = `${event.asset}:${event.assetIssuer ?? 'native'}`;
    for (const [interval, duration] of Object.entries(TIME_SERIES_INTERVALS) as Array<[TimeSeriesInterval, number]>) {
      const start = Math.floor(timestamp / duration) * duration;
      const key = bucketKey(asset, interval, start);
      const existing = this.pending.get(key);
      if (existing) {
        existing.count += 1;
        existing.volume += amount;
        existing.minAmount = Math.min(existing.minAmount, amount);
        existing.maxAmount = Math.max(existing.maxAmount, amount);
        if (event.fromAddress) existing.senders.add(event.fromAddress);
      } else {
        this.pending.set(key, {
          asset,
          interval,
          bucketStart: start,
          count: 1,
          volume: amount,
          minAmount: amount,
          maxAmount: amount,
          senders: new Set(event.fromAddress ? [event.fromAddress] : []),
        });
      }
    }
  }

  /** Flushes buffered increments; a failed write is retained for a later retry. */
  async flush(): Promise<void> {
    if (this.flushPromise) return this.flushPromise;
    this.flushPromise = this.flushPending().finally(() => {
      this.flushPromise = null;
    });
    return this.flushPromise;
  }

  async query(options: {
    interval: TimeSeriesInterval;
    from: Date;
    to: Date;
    asset?: string;
    limit?: number;
  }): Promise<TimeSeriesBucket[]> {
    validateQueryRange(options.from, options.to);
    return this.store.query({
      ...options,
      limit: Math.min(Math.max(options.limit ?? 500, 1), 1000),
    });
  }

  private async flushPending(): Promise<void> {
    while (this.pending.size > 0) {
      const batch = [...this.pending.entries()];
      for (const [key] of batch) this.pending.delete(key);

      for (let index = 0; index < batch.length; index += 1) {
        const [key, bucket] = batch[index];
        try {
          await this.store.upsert(bucket);
        } catch (error) {
          for (const [retryKey, retryBucket] of batch.slice(index)) {
            const newer = this.pending.get(retryKey);
            if (newer) mergePending(retryBucket, newer);
            this.pending.set(retryKey, retryBucket);
          }
          throw error;
        }
      }
    }
  }
}

export function validateQueryRange(from: Date, to: Date): void {
  if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime()) || from >= to) {
    throw new Error('Invalid time-series range: from must be before to');
  }
}

export const timeSeriesRollupEngine = new TimeSeriesRollupEngine();
