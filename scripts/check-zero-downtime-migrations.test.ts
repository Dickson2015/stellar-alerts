import { describe, expect, it } from 'vitest';
import {
  analyzeMigrationSql,
  applyDynamicChecks,
  formatRiskReport,
  parseSafeMigrationPragma,
  type MigrationDbInspector,
} from './check-zero-downtime-migrations';

describe('parseSafeMigrationPragma', () => {
  it('parses case-insensitive pragmas and ignores ordinary comments', () => {
    expect(parseSafeMigrationPragma('-- safe-migration: reviewed by DBA')).toBe('reviewed by DBA');
    expect(parseSafeMigrationPragma('  -- SAFE-MIGRATION: backfill done  ')).toBe('backfill done');
    expect(parseSafeMigrationPragma('-- just a comment')).toBeUndefined();
  });
});

describe('analyzeMigrationSql', () => {
  it('passes safe additive migrations', () => {
    const report = analyzeMigrationSql(`
      CREATE TABLE "AssetWatch" ("id" TEXT NOT NULL);
      ALTER TABLE "Payment" ADD COLUMN "note" TEXT;
      ALTER TABLE "Payment" ADD COLUMN "score" INTEGER NOT NULL DEFAULT 0;
      CREATE INDEX CONCURRENTLY "Payment_note_idx" ON "Payment"("note");
    `, '20261124000000_safe_additive');

    expect(report.passed).toBe(true);
    expect(report.risks).toEqual([]);
    expect(formatRiskReport(report)).toContain('No backward-incompatible');
  });

  it('flags unsafe column drops, renames, type changes and non-null additions', () => {
    const report = analyzeMigrationSql(`
      ALTER TABLE "Payment" DROP COLUMN "legacy";
      ALTER TABLE "Payment" RENAME COLUMN "old" TO "new";
      ALTER TABLE "Payment" ALTER COLUMN "amount" TYPE NUMERIC(20, 4);
      ALTER TABLE "Payment" ADD COLUMN "required" TEXT NOT NULL;
      ALTER TABLE "Payment" ALTER COLUMN "asset" SET NOT NULL;
    `, '20261124000001_unsafe');

    expect(report.passed).toBe(false);
    expect(report.blockingCount).toBe(5);
    expect(report.risks.map((risk) => risk.code)).toEqual([
      'drop_column',
      'rename_column',
      'alter_column_type',
      'add_column_not_null_without_default',
      'set_not_null',
    ]);
    expect(report.risks[0]).toMatchObject({ table: 'Payment', column: 'legacy', severity: 'blocking' });
    for (const risk of report.risks) {
      expect(risk.remediation).toMatch(/deploy|backfill|CONCURRENTLY|drop|typed column/i);
    }
    expect(formatRiskReport(report)).toContain('[BLOCKING] line 2 drop_column (Payment.legacy)');
  });

  it('flags table drops and blocking index builds', () => {
    const report = analyzeMigrationSql(`
      DROP TABLE IF EXISTS "OldPayment";
      CREATE UNIQUE INDEX "Payment_tx_idx" ON "Payment"("txHash");
      CREATE INDEX "Payment_asset_idx" ON "Payment"("asset");
    `);

    expect(report.risks.map((risk) => risk.code)).toEqual([
      'drop_table',
      'create_index_without_concurrently',
      'create_index_without_concurrently',
    ]);
  });

  it('acknowledges a pragma-annotated exception without failing the gate', () => {
    const report = analyzeMigrationSql(`
      -- safe-migration: table is unused; verified by ops in ticket OPS-42
      ALTER TABLE "LegacyQueue" DROP COLUMN "payload";
      ALTER TABLE "Payment" DROP COLUMN "other";
    `);

    expect(report.passed).toBe(false);
    expect(report.blockingCount).toBe(1);
    expect(report.acknowledgedCount).toBe(1);
    expect(report.risks[0]).toMatchObject({
      code: 'drop_column',
      acknowledged: true,
      justification: 'table is unused; verified by ops in ticket OPS-42',
    });
    expect(formatRiskReport(report)).toContain('ACKNOWLEDGED: table is unused');
  });

  it('records accurate line numbers for multi-statement migrations', () => {
    const report = analyzeMigrationSql(`-- initial
CREATE TABLE "A" ("id" TEXT);

ALTER TABLE "A" DROP COLUMN "id";`);
    expect(report.risks[0].line).toBe(4);
  });
});

describe('applyDynamicChecks', () => {
  const inspector = (rows: number): MigrationDbInspector => ({
    countRows: async (table) => {
      expect(table).toBe('Payment');
      return rows;
    },
  });

  it('adds evidence when a NOT NULL column is added to a populated table', async () => {
    const report = analyzeMigrationSql('ALTER TABLE "Payment" ADD COLUMN "memo" TEXT NOT NULL;');
    const checked = await applyDynamicChecks(report, inspector(1500));

    expect(checked.risks).toHaveLength(1);
    expect(checked.risks[0].message).toContain('1500 row(s)');
  });

  it('leaves the report unchanged for an empty table', async () => {
    const report = analyzeMigrationSql('ALTER TABLE "Payment" ADD COLUMN "memo" TEXT NOT NULL;');
    const checked = await applyDynamicChecks(report, inspector(0));
    expect(checked).toEqual(report);
  });
});
