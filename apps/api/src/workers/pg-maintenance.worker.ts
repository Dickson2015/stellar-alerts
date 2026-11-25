/**
 * Online Zero-Lock PostgreSQL Table Compaction & Index Rebuild Scheduler (#991).
 *
 * Monitors dead-tuple bloat ratios across high-churn tables (`WebhookLog`,
 * `IngestionCursor`, and other core tables) via `BloatMonitorService`, and runs
 * throttled `VACUUM (ANALYZE)` and non-blocking `REINDEX INDEX CONCURRENTLY`
 * during low-traffic windows — automatically aborting if replication lag or
 * CPU load exceeds safety thresholds.
 */

import { prisma } from '../lib/prisma';
import { createLogger } from '../lib/logger';
import {
  BloatMonitorService,
  bloatMonitorService,
  CORE_DATABASE_TABLES,
  type BloatThresholds,
  type SafetyGuardResult,
  type SafetyGuardThresholds,
  type TableBloatAssessment,
} from '../modules/database/bloat-monitor.service';

const log = createLogger({ module: 'PgMaintenanceScheduler' });

const PG_IDENTIFIER_RE = /^[A-Za-z_][A-Za-z0-9_$]*$/;
const DEFAULT_THROTTLE_DELAY_MS = 500;
const DEFAULT_MAX_TABLES_PER_CYCLE = 5;
const DEFAULT_INTERVAL_MS = 60 * 60 * 1000; // 1 hour

export class UnsafeMaintenanceSqlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsafeMaintenanceSqlError';
  }
}

export type MaintenanceSqlExecutor = (sql: string) => Promise<void>;
export type MaintenanceSleepFn = (ms: number) => Promise<void>;

export interface MaintenanceCycleOptions {
  tables?: ReadonlyArray<string>;
  bloatThresholds?: BloatThresholds;
  safetyThresholds?: SafetyGuardThresholds;
  throttleDelayMs?: number;
  maxTablesPerCycle?: number;
}

export interface MaintenanceCycleReport {
  status: 'completed' | 'aborted' | 'skipped_busy';
  abortReason?: string;
  evaluatedTables: TableBloatAssessment[];
  vacuumedTables: string[];
  reindexedIndexes: string[];
  executedStatements: string[];
  lastSafetyCheck?: SafetyGuardResult;
  startedAt: string;
  finishedAt: string;
}

/**
 * Validates that a PostgreSQL identifier contains only safe characters.
 */
export function assertSafePgIdentifier(identifier: string): string {
  if (!PG_IDENTIFIER_RE.test(identifier)) {
    throw new UnsafeMaintenanceSqlError(`Unsafe PostgreSQL identifier: "${identifier}"`);
  }
  return identifier;
}

function quotePgIdentifier(identifier: string): string {
  return `"${assertSafePgIdentifier(identifier)}"`;
}

/**
 * Builds a non-blocking `VACUUM (ANALYZE)` statement (never `VACUUM FULL`).
 */
export function buildVacuumAnalyzeSql(schemaName: string, tableName: string): string {
  return `VACUUM (ANALYZE) ${quotePgIdentifier(schemaName)}.${quotePgIdentifier(tableName)}`;
}

/**
 * Builds a non-blocking `REINDEX INDEX CONCURRENTLY` statement that avoids
 * `ACCESS EXCLUSIVE` table locks blocking live ingestion.
 */
export function buildReindexIndexConcurrentlySql(schemaName: string, indexName: string): string {
  return `REINDEX INDEX CONCURRENTLY ${quotePgIdentifier(schemaName)}.${quotePgIdentifier(indexName)}`;
}

/**
 * Concurrency safety guard: verifies that any SQL executed by the maintenance
 * worker is strictly non-blocking and cannot acquire `ACCESS EXCLUSIVE` locks.
 */
export function assertNonBlockingMaintenanceSql(sql: string): void {
  const normalized = sql.trim().replace(/\s+/g, ' ').toUpperCase();

  if (/\bVACUUM\b[^;]*\bFULL\b/.test(normalized)) {
    throw new UnsafeMaintenanceSqlError(
      'Blocked VACUUM FULL: acquires ACCESS EXCLUSIVE lock and blocks live ingestion.',
    );
  }
  if (/\bLOCK\s+TABLE\b|\bACCESS\s+EXCLUSIVE\b/.test(normalized)) {
    throw new UnsafeMaintenanceSqlError(
      'Blocked explicit table lock / ACCESS EXCLUSIVE statement.',
    );
  }
  if (/\bREINDEX\b/.test(normalized) && !/^REINDEX\s+INDEX\s+CONCURRENTLY\s+/.test(normalized)) {
    throw new UnsafeMaintenanceSqlError(
      'Blocked non-concurrent REINDEX: must use REINDEX INDEX CONCURRENTLY to avoid ACCESS EXCLUSIVE locks.',
    );
  }
}

const defaultSqlExecutor: MaintenanceSqlExecutor = async (sql: string) => {
  assertNonBlockingMaintenanceSql(sql);
  await prisma.$executeRawUnsafe(sql);
};

const defaultSleep: MaintenanceSleepFn = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));

export class PgMaintenanceScheduler {
  private readonly monitor: BloatMonitorService;
  private readonly executeSql: MaintenanceSqlExecutor;
  private readonly sleepFn: MaintenanceSleepFn;
  private isRunning = false;
  private timer: NodeJS.Timeout | null = null;

  constructor(options?: {
    monitor?: BloatMonitorService;
    executeSql?: MaintenanceSqlExecutor;
    sleepFn?: MaintenanceSleepFn;
  }) {
    this.monitor = options?.monitor ?? bloatMonitorService;
    this.executeSql = options?.executeSql ?? defaultSqlExecutor;
    this.sleepFn = options?.sleepFn ?? defaultSleep;
  }

  /**
   * Executes one throttled, zero-lock maintenance cycle across core tables.
   *
   * Re-checks replication lag and CPU load before every table and before every
   * individual `REINDEX INDEX CONCURRENTLY` operation, aborting immediately if
   * safety thresholds are exceeded.
   */
  public async runMaintenanceCycle(
    options: MaintenanceCycleOptions = {},
  ): Promise<MaintenanceCycleReport> {
    const startedAt = new Date().toISOString();

    if (this.isRunning) {
      return {
        status: 'skipped_busy',
        abortReason: 'A maintenance cycle is already in progress',
        evaluatedTables: [],
        vacuumedTables: [],
        reindexedIndexes: [],
        executedStatements: [],
        startedAt,
        finishedAt: new Date().toISOString(),
      };
    }

    this.isRunning = true;
    const evaluatedTables: TableBloatAssessment[] = [];
    const vacuumedTables: string[] = [];
    const reindexedIndexes: string[] = [];
    const executedStatements: string[] = [];
    const throttleDelayMs = options.throttleDelayMs ?? DEFAULT_THROTTLE_DELAY_MS;
    const maxTablesPerCycle = options.maxTablesPerCycle ?? DEFAULT_MAX_TABLES_PER_CYCLE;
    const safetyThresholds = options.safetyThresholds ?? {};

    let lastSafetyCheck: SafetyGuardResult | undefined;

    try {
      // Pre-flight safety check
      lastSafetyCheck = await this.monitor.checkSafetyGuards(safetyThresholds);
      if (!lastSafetyCheck.safe) {
        log.warn(
          {
            abortReason: lastSafetyCheck.abortReason,
            replicationLagSeconds: lastSafetyCheck.replicationLagSeconds,
            cpuLoadRatio: lastSafetyCheck.cpuLoadRatio,
          },
          'Aborting PostgreSQL maintenance cycle before start due to safety guard',
        );
        return {
          status: 'aborted',
          abortReason: lastSafetyCheck.abortReason,
          evaluatedTables,
          vacuumedTables,
          reindexedIndexes,
          executedStatements,
          lastSafetyCheck,
          startedAt,
          finishedAt: new Date().toISOString(),
        };
      }

      const assessments = await this.monitor.getTableBloatStats(
        options.tables ?? CORE_DATABASE_TABLES,
        options.bloatThresholds,
      );
      evaluatedTables.push(...assessments);

      const candidates = assessments
        .filter((a) => a.needsVacuum || a.needsReindex)
        .slice(0, maxTablesPerCycle);

      for (const table of candidates) {
        // Re-check safety guard before compacting each table
        lastSafetyCheck = await this.monitor.checkSafetyGuards(safetyThresholds);
        if (!lastSafetyCheck.safe) {
          log.warn(
            { table: table.tableName, abortReason: lastSafetyCheck.abortReason },
            'Aborting PostgreSQL maintenance mid-cycle due to safety guard',
          );
          return {
            status: 'aborted',
            abortReason: lastSafetyCheck.abortReason,
            evaluatedTables,
            vacuumedTables,
            reindexedIndexes,
            executedStatements,
            lastSafetyCheck,
            startedAt,
            finishedAt: new Date().toISOString(),
          };
        }

        if (table.needsVacuum) {
          const vacuumSql = buildVacuumAnalyzeSql(table.schemaName, table.tableName);
          assertNonBlockingMaintenanceSql(vacuumSql);
          await this.executeSql(vacuumSql);
          executedStatements.push(vacuumSql);
          vacuumedTables.push(table.tableName);
          log.info(
            {
              table: table.tableName,
              deadTuplePercent: table.deadTuplePercent,
              nDeadTup: table.nDeadTup,
            },
            'Completed online VACUUM (ANALYZE)',
          );
          if (throttleDelayMs > 0) await this.sleepFn(throttleDelayMs);
        }

        if (table.needsReindex) {
          const indexes = await this.monitor.getTableIndexes(table.schemaName, table.tableName);
          for (const index of indexes) {
            // Re-check safety guard before each individual concurrent index rebuild
            lastSafetyCheck = await this.monitor.checkSafetyGuards(safetyThresholds);
            if (!lastSafetyCheck.safe) {
              log.warn(
                {
                  table: table.tableName,
                  index: index.indexName,
                  abortReason: lastSafetyCheck.abortReason,
                },
                'Aborting REINDEX INDEX CONCURRENTLY mid-table due to safety guard',
              );
              return {
                status: 'aborted',
                abortReason: lastSafetyCheck.abortReason,
                evaluatedTables,
                vacuumedTables,
                reindexedIndexes,
                executedStatements,
                lastSafetyCheck,
                startedAt,
                finishedAt: new Date().toISOString(),
              };
            }

            const reindexSql = buildReindexIndexConcurrentlySql(index.schemaName, index.indexName);
            assertNonBlockingMaintenanceSql(reindexSql);
            await this.executeSql(reindexSql);
            executedStatements.push(reindexSql);
            reindexedIndexes.push(index.indexName);
            log.info(
              { table: table.tableName, index: index.indexName },
              'Completed non-blocking REINDEX INDEX CONCURRENTLY',
            );
            if (throttleDelayMs > 0) await this.sleepFn(throttleDelayMs);
          }
        }
      }

      return {
        status: 'completed',
        evaluatedTables,
        vacuumedTables,
        reindexedIndexes,
        executedStatements,
        lastSafetyCheck,
        startedAt,
        finishedAt: new Date().toISOString(),
      };
    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Starts periodic low-traffic maintenance cycles.
   */
  public start(
    intervalMs: number = DEFAULT_INTERVAL_MS,
    options: MaintenanceCycleOptions = {},
  ): void {
    if (this.timer) return;
    const scheduledOptions: MaintenanceCycleOptions = {
      ...options,
      safetyThresholds: {
        enforceLowTrafficWindow: true,
        ...options.safetyThresholds,
      },
    };
    this.timer = setInterval(() => {
      void this.runMaintenanceCycle(scheduledOptions).catch((err: unknown) => {
        log.error(
          { err: err instanceof Error ? err.message : String(err) },
          'PostgreSQL maintenance cycle failed',
        );
      });
    }, intervalMs);
    this.timer.unref();
    log.info({ intervalMs }, 'Started PgMaintenanceScheduler');
  }

  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}

export const pgMaintenanceScheduler = new PgMaintenanceScheduler();
