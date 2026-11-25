/**
 * PostgreSQL Dead-Tuple Bloat Monitor & Safety Guard Service (#991).
 *
 * Queries `pg_stat_user_tables` to track `n_dead_tup` vs `n_live_tup` ratios across
 * core high-churn tables (`WebhookLog`, `IngestionCursor`, etc.) and evaluates
 * replication-lag / CPU-load safety thresholds before online maintenance.
 */

import os from 'node:os';
import { prisma } from '../../lib/prisma';
import { createLogger } from '../../lib/logger';

const log = createLogger({ module: 'BloatMonitorService' });

export const CORE_DATABASE_TABLES = [
  'WebhookLog',
  'IngestionCursor',
  'Payment',
  'OutboxEvent',
  'NotificationDelivery',
  'NotificationDeliveryAttempt',
  'DeadLetter',
  'DeliveryLog',
  'DeduplicationLog',
] as const;

export const DEFAULT_MIN_DEAD_TUPLES = 1_000;
export const DEFAULT_VACUUM_BLOAT_RATIO = 0.15; // 15% dead tuples
export const DEFAULT_REINDEX_BLOAT_RATIO = 0.30; // 30% dead tuples
export const DEFAULT_MAX_REPLICATION_LAG_SECONDS = 5;
export const DEFAULT_MAX_CPU_LOAD_RATIO = 0.75;

export interface RawPgTableStat {
  schemaname: string;
  relname: string;
  n_live_tup: number | bigint | string;
  n_dead_tup: number | bigint | string;
  last_vacuum?: Date | string | null;
  last_autovacuum?: Date | string | null;
  last_analyze?: Date | string | null;
  last_autoanalyze?: Date | string | null;
}

export interface BloatThresholds {
  minDeadTuples?: number;
  vacuumThresholdRatio?: number;
  reindexThresholdRatio?: number;
}

export interface TableBloatAssessment {
  schemaName: string;
  tableName: string;
  nLiveTup: number;
  nDeadTup: number;
  /** n_dead_tup / (n_live_tup + n_dead_tup), in [0, 1] */
  deadTupleRatio: number;
  deadTuplePercent: number;
  needsVacuum: boolean;
  needsReindex: boolean;
  priority: 'critical' | 'high' | 'normal';
  lastAutovacuum: Date | null;
  lastAutoanalyze: Date | null;
}

export interface SafetyGuardThresholds {
  maxReplicationLagSeconds?: number;
  maxCpuLoadRatio?: number;
  enforceLowTrafficWindow?: boolean;
  lowTrafficStartHourUtc?: number;
  lowTrafficEndHourUtc?: number;
  now?: Date;
}

export interface SafetyGuardResult {
  safe: boolean;
  replicationLagSeconds: number;
  cpuLoadRatio: number;
  withinTrafficWindow: boolean;
  abortReason?: string;
}

export interface PgIndexInfo {
  schemaName: string;
  tableName: string;
  indexName: string;
  isValid: boolean;
}

export interface BloatQueryAdapter {
  queryTableStats(tables: ReadonlyArray<string>): Promise<RawPgTableStat[]>;
  queryTableIndexes(schemaName: string, tableName: string): Promise<PgIndexInfo[]>;
  queryReplicationLagSeconds(): Promise<number>;
  getCpuLoadRatio(): Promise<number>;
}

function toSafeNumber(val: number | bigint | string | null | undefined): number {
  if (typeof val === 'number') return Number.isFinite(val) ? val : 0;
  if (typeof val === 'bigint') return Number(val);
  if (typeof val === 'string') {
    const parsed = Number(val);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

function toDateOrNull(val: Date | string | null | undefined): Date | null {
  if (!val) return null;
  return val instanceof Date ? val : new Date(val);
}

/**
 * Pure bloat ratio evaluator.
 *
 * Computes `deadTupleRatio = n_dead_tup / (n_live_tup + n_dead_tup)` and decides
 * whether the table requires `VACUUM (ANALYZE)` and/or `REINDEX INDEX CONCURRENTLY`.
 */
export function evaluateTableBloat(
  stat: RawPgTableStat,
  thresholds: BloatThresholds = {},
): TableBloatAssessment {
  const minDeadTuples = thresholds.minDeadTuples ?? DEFAULT_MIN_DEAD_TUPLES;
  const vacuumThresholdRatio = thresholds.vacuumThresholdRatio ?? DEFAULT_VACUUM_BLOAT_RATIO;
  const reindexThresholdRatio = thresholds.reindexThresholdRatio ?? DEFAULT_REINDEX_BLOAT_RATIO;

  const nLiveTup = Math.max(0, toSafeNumber(stat.n_live_tup));
  const nDeadTup = Math.max(0, toSafeNumber(stat.n_dead_tup));
  const totalTuples = nLiveTup + nDeadTup;

  const deadTupleRatio = totalTuples > 0 ? Number((nDeadTup / totalTuples).toFixed(4)) : 0;
  const deadTuplePercent = Number((deadTupleRatio * 100).toFixed(2));

  const meetsMinimumVolume = nDeadTup >= minDeadTuples;
  const needsReindex = meetsMinimumVolume && deadTupleRatio >= reindexThresholdRatio;
  const needsVacuum = meetsMinimumVolume && deadTupleRatio >= vacuumThresholdRatio;

  const priority: 'critical' | 'high' | 'normal' = needsReindex
    ? 'critical'
    : needsVacuum
      ? 'high'
      : 'normal';

  return {
    schemaName: stat.schemaname || 'public',
    tableName: stat.relname,
    nLiveTup,
    nDeadTup,
    deadTupleRatio,
    deadTuplePercent,
    needsVacuum,
    needsReindex,
    priority,
    lastAutovacuum: toDateOrNull(stat.last_autovacuum),
    lastAutoanalyze: toDateOrNull(stat.last_autoanalyze),
  };
}

/**
 * Checks whether a UTC timestamp falls inside the configured low-traffic window
 * (handles both same-day windows like 01:00–05:00 and overnight windows like 23:00–04:00).
 */
export function isWithinLowTrafficWindow(
  now: Date,
  startHourUtc = 1,
  endHourUtc = 5,
): boolean {
  const hour = now.getUTCHours();
  if (startHourUtc === endHourUtc) return true;
  if (startHourUtc < endHourUtc) {
    return hour >= startHourUtc && hour < endHourUtc;
  }
  return hour >= startHourUtc || hour < endHourUtc;
}

/**
 * Pure concurrency & database health safety guard evaluator.
 */
export function evaluateSafetyGuards(
  metrics: { replicationLagSeconds: number; cpuLoadRatio: number },
  thresholds: SafetyGuardThresholds = {},
): SafetyGuardResult {
  const maxReplicationLagSeconds =
    thresholds.maxReplicationLagSeconds ?? DEFAULT_MAX_REPLICATION_LAG_SECONDS;
  const maxCpuLoadRatio = thresholds.maxCpuLoadRatio ?? DEFAULT_MAX_CPU_LOAD_RATIO;
  const enforceWindow = thresholds.enforceLowTrafficWindow ?? false;
  const now = thresholds.now ?? new Date();
  const withinTrafficWindow = enforceWindow
    ? isWithinLowTrafficWindow(
        now,
        thresholds.lowTrafficStartHourUtc ?? 1,
        thresholds.lowTrafficEndHourUtc ?? 5,
      )
    : true;

  if (!withinTrafficWindow) {
    return {
      safe: false,
      replicationLagSeconds: metrics.replicationLagSeconds,
      cpuLoadRatio: metrics.cpuLoadRatio,
      withinTrafficWindow: false,
      abortReason: `Outside low-traffic maintenance window (current UTC hour: ${now.getUTCHours()})`,
    };
  }

  if (metrics.replicationLagSeconds > maxReplicationLagSeconds) {
    return {
      safe: false,
      replicationLagSeconds: metrics.replicationLagSeconds,
      cpuLoadRatio: metrics.cpuLoadRatio,
      withinTrafficWindow,
      abortReason: `Replication lag (${metrics.replicationLagSeconds.toFixed(2)}s) exceeds safety threshold (${maxReplicationLagSeconds}s)`,
    };
  }

  if (metrics.cpuLoadRatio > maxCpuLoadRatio) {
    return {
      safe: false,
      replicationLagSeconds: metrics.replicationLagSeconds,
      cpuLoadRatio: metrics.cpuLoadRatio,
      withinTrafficWindow,
      abortReason: `CPU load ratio (${(metrics.cpuLoadRatio * 100).toFixed(1)}%) exceeds safety threshold (${(maxCpuLoadRatio * 100).toFixed(1)}%)`,
    };
  }

  return {
    safe: true,
    replicationLagSeconds: metrics.replicationLagSeconds,
    cpuLoadRatio: metrics.cpuLoadRatio,
    withinTrafficWindow,
  };
}

const defaultPrismaAdapter: BloatQueryAdapter = {
  async queryTableStats(tables: ReadonlyArray<string>): Promise<RawPgTableStat[]> {
    const rows = await prisma.$queryRawUnsafe<RawPgTableStat[]>(
      `
        SELECT
          schemaname,
          relname,
          n_live_tup,
          n_dead_tup,
          last_vacuum,
          last_autovacuum,
          last_analyze,
          last_autoanalyze
        FROM pg_stat_user_tables
        WHERE relname = ANY($1::text[])
        ORDER BY n_dead_tup DESC
      `,
      Array.from(tables),
    );
    return rows;
  },

  async queryTableIndexes(schemaName: string, tableName: string): Promise<PgIndexInfo[]> {
    const rows = await prisma.$queryRawUnsafe<
      Array<{ schemaname: string; tablename: string; indexname: string; indisvalid: boolean }>
    >(
      `
        SELECT
          ns.nspname AS schemaname,
          tbl.relname AS tablename,
          idx.relname AS indexname,
          i.indisvalid AS indisvalid
        FROM pg_index i
        JOIN pg_class tbl ON tbl.oid = i.indrelid
        JOIN pg_class idx ON idx.oid = i.indexrelid
        JOIN pg_namespace ns ON ns.oid = tbl.relnamespace
        WHERE ns.nspname = $1
          AND tbl.relname = $2
          AND i.indisvalid = true
        ORDER BY idx.relname ASC
      `,
      schemaName,
      tableName,
    );

    return rows.map((row) => ({
      schemaName: row.schemaname,
      tableName: row.tablename,
      indexName: row.indexname,
      isValid: Boolean(row.indisvalid),
    }));
  },

  async queryReplicationLagSeconds(): Promise<number> {
    try {
      const rows = await prisma.$queryRawUnsafe<Array<{ lag_seconds: number | string | null }>>(
        `
          SELECT COALESCE(MAX(EXTRACT(EPOCH FROM replay_lag)), 0) AS lag_seconds
          FROM pg_stat_replication
        `,
      );
      return toSafeNumber(rows[0]?.lag_seconds ?? 0);
    } catch (err: unknown) {
      log.debug(
        { err: err instanceof Error ? err.message : String(err) },
        'pg_stat_replication unavailable; assuming 0s lag',
      );
      return 0;
    }
  },

  async getCpuLoadRatio(): Promise<number> {
    const cpuCount = Math.max(1, os.cpus().length);
    const load1m = os.loadavg()[0] ?? 0;
    return Number((load1m / cpuCount).toFixed(4));
  },
};

export class BloatMonitorService {
  private readonly adapter: BloatQueryAdapter;
  private readonly defaultThresholds: BloatThresholds;

  constructor(adapter?: BloatQueryAdapter, thresholds: BloatThresholds = {}) {
    this.adapter = adapter ?? defaultPrismaAdapter;
    this.defaultThresholds = thresholds;
  }

  /**
   * Monitors `n_dead_tup` vs `n_live_tup` ratios across core database tables via `pg_stat_user_tables`.
   */
  public async getTableBloatStats(
    tables: ReadonlyArray<string> = CORE_DATABASE_TABLES,
    thresholds?: BloatThresholds,
  ): Promise<TableBloatAssessment[]> {
    const rawStats = await this.adapter.queryTableStats(tables);
    const merged = { ...this.defaultThresholds, ...thresholds };
    return rawStats
      .map((row) => evaluateTableBloat(row, merged))
      .sort((a, b) => b.deadTupleRatio - a.deadTupleRatio || b.nDeadTup - a.nDeadTup);
  }

  /**
   * Lists valid indexes on a table eligible for online `REINDEX INDEX CONCURRENTLY`.
   */
  public async getTableIndexes(schemaName: string, tableName: string): Promise<PgIndexInfo[]> {
    const indexes = await this.adapter.queryTableIndexes(schemaName, tableName);
    return indexes.filter((idx) => idx.isValid);
  }

  /**
   * Evaluates live replication lag and CPU load safety guards.
   */
  public async checkSafetyGuards(
    thresholds: SafetyGuardThresholds = {},
  ): Promise<SafetyGuardResult> {
    const [replicationLagSeconds, cpuLoadRatio] = await Promise.all([
      this.adapter.queryReplicationLagSeconds(),
      this.adapter.getCpuLoadRatio(),
    ]);
    return evaluateSafetyGuards({ replicationLagSeconds, cpuLoadRatio }, thresholds);
  }
}

export const bloatMonitorService = new BloatMonitorService();
