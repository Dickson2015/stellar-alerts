import { describe, it, expect, vi } from 'vitest';
import {
  BloatMonitorService,
  evaluateSafetyGuards,
  evaluateTableBloat,
  isWithinLowTrafficWindow,
  type BloatQueryAdapter,
} from '../../modules/database/bloat-monitor.service';
import {
  PgMaintenanceScheduler,
  UnsafeMaintenanceSqlError,
  assertNonBlockingMaintenanceSql,
  assertSafePgIdentifier,
  buildReindexIndexConcurrentlySql,
  buildVacuumAnalyzeSql,
} from '../pg-maintenance.worker';

describe('PostgreSQL Bloat Ratio Evaluator (#991)', () => {
  it('computes n_dead_tup vs n_live_tup ratios and classifies vacuum/reindex priority', () => {
    // 40% dead tuples on WebhookLog -> critical (needs both VACUUM ANALYZE and REINDEX CONCURRENTLY)
    const critical = evaluateTableBloat({
      schemaname: 'public',
      relname: 'WebhookLog',
      n_live_tup: 60_000n,
      n_dead_tup: 40_000n,
    });
    expect(critical.deadTupleRatio).toBe(0.4);
    expect(critical.deadTuplePercent).toBe(40);
    expect(critical.needsVacuum).toBe(true);
    expect(critical.needsReindex).toBe(true);
    expect(critical.priority).toBe('critical');

    // 20% dead tuples on IngestionCursor -> high (needs VACUUM ANALYZE only)
    const moderate = evaluateTableBloat({
      schemaname: 'public',
      relname: 'IngestionCursor',
      n_live_tup: '8000',
      n_dead_tup: '2000',
    });
    expect(moderate.deadTupleRatio).toBe(0.2);
    expect(moderate.needsVacuum).toBe(true);
    expect(moderate.needsReindex).toBe(false);
    expect(moderate.priority).toBe('high');

    // Healthy table (5% dead tuples) -> normal
    const healthy = evaluateTableBloat({
      schemaname: 'public',
      relname: 'Payment',
      n_live_tup: 95_000,
      n_dead_tup: 5_000,
    });
    expect(healthy.needsVacuum).toBe(false);
    expect(healthy.needsReindex).toBe(false);
    expect(healthy.priority).toBe('normal');

    // Tiny table below minDeadTuples threshold even with high percentage -> skipped
    const tiny = evaluateTableBloat({
      schemaname: 'public',
      relname: 'DeadLetter',
      n_live_tup: 50,
      n_dead_tup: 100,
    });
    expect(tiny.needsVacuum).toBe(false);
    expect(tiny.needsReindex).toBe(false);
  });
});

describe('Concurrency & Safety Guard Checks (#991)', () => {
  it('allows non-blocking VACUUM (ANALYZE) and REINDEX INDEX CONCURRENTLY SQL', () => {
    const vacuumSql = buildVacuumAnalyzeSql('public', 'WebhookLog');
    const reindexSql = buildReindexIndexConcurrentlySql('public', 'WebhookLog_createdAt_idx');

    expect(vacuumSql).toBe('VACUUM (ANALYZE) "public"."WebhookLog"');
    expect(reindexSql).toBe('REINDEX INDEX CONCURRENTLY "public"."WebhookLog_createdAt_idx"');
    expect(() => assertNonBlockingMaintenanceSql(vacuumSql)).not.toThrow();
    expect(() => assertNonBlockingMaintenanceSql(reindexSql)).not.toThrow();
  });

  it('rejects blocking DDL (VACUUM FULL, non-concurrent REINDEX, ACCESS EXCLUSIVE) and unsafe identifiers', () => {
    expect(() => assertNonBlockingMaintenanceSql('VACUUM FULL "public"."WebhookLog"')).toThrow(
      UnsafeMaintenanceSqlError,
    );
    expect(() => assertNonBlockingMaintenanceSql('REINDEX TABLE "public"."WebhookLog"')).toThrow(
      UnsafeMaintenanceSqlError,
    );
    expect(() =>
      assertNonBlockingMaintenanceSql('REINDEX INDEX "public"."WebhookLog_pkey"'),
    ).toThrow(UnsafeMaintenanceSqlError);
    expect(() =>
      assertNonBlockingMaintenanceSql('LOCK TABLE "public"."WebhookLog" IN ACCESS EXCLUSIVE MODE'),
    ).toThrow(UnsafeMaintenanceSqlError);
    expect(() => assertSafePgIdentifier('WebhookLog; DROP TABLE User--')).toThrow(
      UnsafeMaintenanceSqlError,
    );
  });

  it('aborts when replication lag, CPU load, or traffic window violates safety thresholds', () => {
    const safeCheck = evaluateSafetyGuards(
      { replicationLagSeconds: 1.2, cpuLoadRatio: 0.35 },
      {
        maxReplicationLagSeconds: 5,
        maxCpuLoadRatio: 0.75,
        enforceLowTrafficWindow: true,
        lowTrafficStartHourUtc: 1,
        lowTrafficEndHourUtc: 5,
        now: new Date('2026-11-25T03:00:00Z'),
      },
    );
    expect(safeCheck.safe).toBe(true);

    const highLag = evaluateSafetyGuards({ replicationLagSeconds: 9.5, cpuLoadRatio: 0.2 });
    expect(highLag.safe).toBe(false);
    expect(highLag.abortReason).toContain('Replication lag');

    const highCpu = evaluateSafetyGuards({ replicationLagSeconds: 0.5, cpuLoadRatio: 0.91 });
    expect(highCpu.safe).toBe(false);
    expect(highCpu.abortReason).toContain('CPU load');

    expect(isWithinLowTrafficWindow(new Date('2026-11-25T14:00:00Z'), 1, 5)).toBe(false);
    expect(isWithinLowTrafficWindow(new Date('2026-11-25T02:30:00Z'), 1, 5)).toBe(true);
  });
});

describe('PgMaintenanceScheduler (#991)', () => {
  it('runs throttled VACUUM (ANALYZE) and REINDEX INDEX CONCURRENTLY on bloated tables', async () => {
    const executed: string[] = [];
    const adapter: BloatQueryAdapter = {
      queryTableStats: vi.fn(async () => [
        { schemaname: 'public', relname: 'WebhookLog', n_live_tup: 50_000, n_dead_tup: 50_000 },
        { schemaname: 'public', relname: 'IngestionCursor', n_live_tup: 8_000, n_dead_tup: 2_000 },
        { schemaname: 'public', relname: 'Payment', n_live_tup: 100_000, n_dead_tup: 500 },
      ]),
      queryTableIndexes: vi.fn(async (_schema, table) =>
        table === 'WebhookLog'
          ? [
              { schemaName: 'public', tableName: 'WebhookLog', indexName: 'WebhookLog_pkey', isValid: true },
              { schemaName: 'public', tableName: 'WebhookLog', indexName: 'WebhookLog_createdAt_idx', isValid: true },
            ]
          : [],
      ),
      queryReplicationLagSeconds: vi.fn(async () => 0.4),
      getCpuLoadRatio: vi.fn(async () => 0.25),
    };

    const monitor = new BloatMonitorService(adapter);
    const scheduler = new PgMaintenanceScheduler({
      monitor,
      executeSql: async (sql) => {
        executed.push(sql);
      },
      sleepFn: vi.fn(async () => undefined),
    });

    const report = await scheduler.runMaintenanceCycle({ throttleDelayMs: 10 });

    expect(report.status).toBe('completed');
    expect(report.vacuumedTables).toEqual(['WebhookLog', 'IngestionCursor']);
    expect(report.reindexedIndexes).toEqual(['WebhookLog_pkey', 'WebhookLog_createdAt_idx']);
    expect(executed).toEqual([
      'VACUUM (ANALYZE) "public"."WebhookLog"',
      'REINDEX INDEX CONCURRENTLY "public"."WebhookLog_pkey"',
      'REINDEX INDEX CONCURRENTLY "public"."WebhookLog_createdAt_idx"',
      'VACUUM (ANALYZE) "public"."IngestionCursor"',
    ]);
  });

  it('aborts maintenance automatically mid-cycle when replication lag spikes above threshold', async () => {
    const executed: string[] = [];
    let lagCall = 0;

    const adapter: BloatQueryAdapter = {
      queryTableStats: vi.fn(async () => [
        { schemaname: 'public', relname: 'WebhookLog', n_live_tup: 50_000, n_dead_tup: 50_000 },
      ]),
      queryTableIndexes: vi.fn(async () => [
        { schemaName: 'public', tableName: 'WebhookLog', indexName: 'WebhookLog_pkey', isValid: true },
        { schemaName: 'public', tableName: 'WebhookLog', indexName: 'WebhookLog_createdAt_idx', isValid: true },
      ]),
      // Pre-flight (0.5s), before table (0.5s), before 1st index (0.5s), before 2nd index -> SPIKE (12.0s)!
      queryReplicationLagSeconds: vi.fn(async () => {
        lagCall++;
        return lagCall >= 4 ? 12.0 : 0.5;
      }),
      getCpuLoadRatio: vi.fn(async () => 0.2),
    };

    const monitor = new BloatMonitorService(adapter);
    const scheduler = new PgMaintenanceScheduler({
      monitor,
      executeSql: async (sql) => {
        executed.push(sql);
      },
      sleepFn: vi.fn(async () => undefined),
    });

    const report = await scheduler.runMaintenanceCycle({
      throttleDelayMs: 0,
      safetyThresholds: { maxReplicationLagSeconds: 5 },
    });

    expect(report.status).toBe('aborted');
    expect(report.abortReason).toContain('Replication lag (12.00s) exceeds safety threshold (5s)');
    // Stopped before the second index!
    expect(report.reindexedIndexes).toEqual(['WebhookLog_pkey']);
    expect(executed).toHaveLength(2);
  });
});
