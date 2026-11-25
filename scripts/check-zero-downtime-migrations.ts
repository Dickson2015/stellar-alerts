#!/usr/bin/env tsx

/**
 * Zero-downtime migration gate (#1047).
 *
 * Statically analyzes Prisma migration SQL for DDL that breaks version N pods
 * while version N+1 rolls out, or that takes blocking table locks. Reviewed
 * exceptions must carry a `-- safe-migration: <justification>` comment on the
 * line immediately before the statement.
 *
 * Usage:
 *   npx tsx scripts/check-zero-downtime-migrations.ts [--base origin/contribution] [--all]
 *   npx tsx scripts/check-zero-downtime-migrations.ts --migration 20261124000000_add_thing
 *   npx tsx scripts/check-zero-downtime-migrations.ts --database-url postgres://...
 */

import { execFileSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import path from 'path';
import { pathToFileURL } from 'url';
import { getMigrations, MIGRATIONS_DIR } from './verify-migrations';

export type RiskSeverity = 'blocking' | 'warning';

export type RiskCode =
  | 'drop_table'
  | 'drop_column'
  | 'rename_column'
  | 'alter_column_type'
  | 'add_column_not_null_without_default'
  | 'set_not_null'
  | 'create_index_without_concurrently';

export interface MigrationRisk {
  code: RiskCode;
  severity: RiskSeverity;
  line: number;
  statement: string;
  table?: string;
  column?: string;
  message: string;
  remediation: string;
  justification?: string;
  acknowledged: boolean;
}

export interface MigrationRiskReport {
  migration: string;
  risks: MigrationRisk[];
  blockingCount: number;
  acknowledgedCount: number;
  passed: boolean;
}

interface SqlStatement {
  text: string;
  startLine: number;
  justification?: string;
}

const REMEDIATIONS: Record<RiskCode, string> = {
  drop_table: 'Expand first (stop reads/writes), deploy, then drop the table in a later release.',
  drop_column: 'Stop reading the column in version N, deploy, then drop it in a later release.',
  rename_column: 'Add the new column, dual-write and backfill, switch readers, then drop the old column.',
  alter_column_type: 'Add a new typed column, backfill it, switch readers, then remove the old column.',
  add_column_not_null_without_default: 'Add the column nullable with a DEFAULT, backfill existing rows, then enforce NOT NULL.',
  set_not_null: 'Backfill existing NULLs first, then set NOT NULL in a later release.',
  create_index_without_concurrently: 'Use CREATE INDEX CONCURRENTLY (outside a transaction block) to avoid a table lock.',
};

const MESSAGES: Record<RiskCode, string> = {
  drop_table: 'Dropping a table immediately breaks the still-running previous version.',
  drop_column: 'Dropping a column breaks the still-running previous version.',
  rename_column: 'Renaming a column is a drop+add for the previous version.',
  alter_column_type: 'Changing a column type breaks readers that expect the old type.',
  add_column_not_null_without_default: 'Adding NOT NULL without a DEFAULT fails on existing rows.',
  set_not_null: 'Setting NOT NULL can fail while old rows still contain NULLs.',
  create_index_without_concurrently: 'A non-concurrent index build takes a table lock during deployment.',
};

/** Parses a `-- safe-migration: reason` line, returning the trimmed justification. */
export function parseSafeMigrationPragma(line: string): string | undefined {
  const match = /^\s*--\s*safe-migration:\s*(.+?)\s*$/i.exec(line);
  return match?.[1]?.trim() || undefined;
}

function stripComments(statement: string): string {
  return statement.split('\n').map((line) => line.replace(/--.*$/, '')).join('\n');
}

function splitStatements(sql: string): SqlStatement[] {
  const statements: SqlStatement[] = [];
  let buffer = '';
  let startLine = 1;
  let justification: string | undefined;

  const flush = () => {
    const text = buffer.trim();
    if (text) statements.push({ text, startLine, justification });
    buffer = '';
    justification = undefined;
  };

  sql.split('\n').forEach((line, index) => {
    const pragma = parseSafeMigrationPragma(line);
    if (pragma) {
      justification = pragma;
      return;
    }
    if (!buffer.trim()) startLine = index + 1;
    buffer += `${line}\n`;
    if (line.includes(';')) flush();
  });
  flush();

  return statements;
}

function tableFrom(sql: string): string | undefined {
  return /ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:"([^"]+)"|([A-Za-z_][\w.]*))/i.exec(sql)?.slice(1).find(Boolean);
}

function riskFor(statement: SqlStatement): MigrationRisk[] {
  const sql = stripComments(statement.text);
  const risks: MigrationRisk[] = [];

  const add = (code: RiskCode, table?: string, column?: string) => {
    risks.push({
      code,
      severity: 'blocking',
      line: statement.startLine,
      statement: statement.text.trim().replace(/\s+/g, ' ').slice(0, 240),
      table,
      column,
      message: MESSAGES[code],
      remediation: REMEDIATIONS[code],
      justification: statement.justification,
      acknowledged: Boolean(statement.justification),
    });
  };

  const dropTable = /\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:"([^"]+)"|([A-Za-z_][\w.]*))/i.exec(sql);
  if (dropTable) add('drop_table', dropTable[1] ?? dropTable[2]);

  const dropColumn = /\bDROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?(?:"([^"]+)"|([A-Za-z_][\w]*))/i.exec(sql);
  if (dropColumn) add('drop_column', tableFrom(sql), dropColumn[1] ?? dropColumn[2]);

  const renameColumn = /\bRENAME\s+(?:COLUMN\s+)?(?:"([^"]+)"|([A-Za-z_][\w]*))\s+TO\s+/i.exec(sql);
  if (renameColumn) add('rename_column', tableFrom(sql), renameColumn[1] ?? renameColumn[2]);

  const alterType = /\bALTER\s+COLUMN\s+(?:"([^"]+)"|([A-Za-z_][\w]*))\s+(?:SET\s+DATA\s+)?TYPE\b/i.exec(sql);
  if (alterType) add('alter_column_type', tableFrom(sql), alterType[1] ?? alterType[2]);

  const addColumn = /\bADD\s+(?:COLUMN\s+)(?:IF\s+NOT\s+EXISTS\s+)?(?:"([^"]+)"|([A-Za-z_][\w]*))\s+[\w[\]()., ]+?(?=NOT\s+NULL|DEFAULT|,|$)/i.exec(sql);
  if (addColumn && /\bNOT\s+NULL\b/i.test(sql) && !/\bDEFAULT\b/i.test(sql)) {
    add('add_column_not_null_without_default', tableFrom(sql), addColumn[1] ?? addColumn[2]);
  }

  if (/\bSET\s+NOT\s+NULL\b/i.test(sql)) add('set_not_null', tableFrom(sql));

  const createIndex = /\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:"([^"]+)"|([A-Za-z_][\w]*))/i.exec(sql);
  if (createIndex && !/\bCONCURRENTLY\b/i.test(sql)) {
    add('create_index_without_concurrently', undefined, createIndex[1] ?? createIndex[2]);
  }

  return risks;
}

/** Analyzes one migration's SQL and classifies every risky DDL statement. */
export function analyzeMigrationSql(sql: string, migration = 'inline'): MigrationRiskReport {
  const risks = splitStatements(sql).flatMap(riskFor);
  const blockingCount = risks.filter((risk) => risk.severity === 'blocking' && !risk.acknowledged).length;
  const acknowledgedCount = risks.filter((risk) => risk.acknowledged).length;

  return {
    migration,
    risks,
    blockingCount,
    acknowledgedCount,
    passed: blockingCount === 0,
  };
}

/** Human-readable risk classification report with remediation guidance. */
export function formatRiskReport(report: MigrationRiskReport): string {
  const lines = [
    `[zero-downtime] ${report.migration}: ${report.passed ? 'PASS' : 'FAIL'} ` +
      `(${report.blockingCount} blocking, ${report.acknowledgedCount} acknowledged)`,
  ];

  for (const risk of report.risks) {
    const location = [risk.table, risk.column].filter(Boolean).join('.');
    const status = risk.acknowledged ? `ACKNOWLEDGED: ${risk.justification}` : risk.severity.toUpperCase();
    lines.push(`  [${status}] line ${risk.line} ${risk.code}${location ? ` (${location})` : ''}`);
    lines.push(`    ${risk.message}`);
    lines.push(`    Fix: ${risk.remediation}`);
  }

  if (report.passed && report.risks.length === 0) {
    lines.push('  No backward-incompatible or lock-heavy DDL detected.');
  }
  return lines.join('\n');
}

/** Minimal interface for the optional dynamic row-shape check. */
export interface MigrationDbInspector {
  countRows(table: string): Promise<number>;
}

/**
 * Adds a dynamic finding when a NOT NULL column is being added to a populated
 * table. Rows existing during a rolling deploy is exactly the failure mode the
 * static rule predicts.
 */
export async function applyDynamicChecks(
  report: MigrationRiskReport,
  inspector: MigrationDbInspector
): Promise<MigrationRiskReport> {
  const dynamicRisks: MigrationRisk[] = [];

  for (const risk of report.risks) {
    if (risk.code !== 'add_column_not_null_without_default' || !risk.table) continue;
    const rows = await inspector.countRows(risk.table);
    if (rows <= 0) continue;
    dynamicRisks.push({
      ...risk,
      code: 'add_column_not_null_without_default',
      message: `${risk.message} The table currently has ${rows} row(s).`,
      justification: risk.justification,
      acknowledged: risk.acknowledged,
    });
  }

  if (dynamicRisks.length === 0) return report;
  const risks = [...report.risks.filter((risk) => !dynamicRisks.some((dynamic) =>
    dynamic.code === risk.code && dynamic.line === risk.line)), ...dynamicRisks];
  return { ...report, risks };
}

function changedMigrations(base: string): string[] {
  const output = execFileSync('git', [
    'diff', '--name-only', `${base}...HEAD`, '--', 'apps/api/prisma/migrations',
  ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });

  const known = new Set(getMigrations());
  const names = output.split('\n')
    .filter(Boolean)
    .map((file) => path.basename(path.dirname(file)))
    .filter((name) => known.has(name));
  return [...new Set(names)].sort();
}

function pgInspector(databaseUrl: string): MigrationDbInspector {
  // Loaded lazily so static analysis needs no database driver configured.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { Client } = require('pg') as { Client: new (config: { connectionString: string }) => {
    connect(): Promise<void>;
    query(text: string, values: string[]): Promise<{ rows: Array<{ count: string }> }>;
    end(): Promise<void>;
  } };

  return {
    async countRows(table: string) {
      // Table names cannot be bound as query parameters; validate and quote.
      if (!/^[A-Za-z_][\w.]*$/.test(table)) {
        throw new Error(`Unsafe table name from migration SQL: ${table}`);
      }
      const quoted = table.split('.').map((part) => `"${part}"`).join('.');
      const client = new Client({ connectionString: databaseUrl });
      await client.connect();
      try {
        const result = await client.query(`SELECT COUNT(*)::text AS count FROM ${quoted}`, []);
        return Number(result.rows[0]?.count ?? 0);
      } finally {
        await client.end();
      }
    },
  };
}

export interface GateOptions {
  base?: string;
  all?: boolean;
  migration?: string;
  databaseUrl?: string;
}

export async function runGate(options: GateOptions): Promise<MigrationRiskReport[]> {
  let migrations: string[];
  if (options.migration) {
    migrations = [options.migration];
  } else if (options.all) {
    migrations = getMigrations();
  } else {
    migrations = changedMigrations(options.base ?? 'origin/contribution');
  }

  const reports: MigrationRiskReport[] = [];
  for (const migration of migrations) {
    const file = path.join(MIGRATIONS_DIR, migration, 'migration.sql');
    if (!existsSync(file)) {
      throw new Error(`Migration not found: ${migration}`);
    }
    let report = analyzeMigrationSql(readFileSync(file, 'utf8'), migration);
    if (options.databaseUrl) report = await applyDynamicChecks(report, pgInspector(options.databaseUrl));
    reports.push(report);
  }
  return reports;
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(`Usage: npx tsx scripts/check-zero-downtime-migrations.ts [options]

Options:
  --base <ref>          Git ref to diff against (default: origin/contribution)
  --all                 Scan every migration instead of only changed ones
  --migration <name>    Scan one migration directory by name
  --database-url <url>  Also run dynamic row-shape checks against PostgreSQL
  -h, --help            Show this help`);
    return 0;
  }

  const option = (name: string) => {
    const index = argv.indexOf(name);
    return index >= 0 ? argv[index + 1] : undefined;
  };

  try {
    const reports = await runGate({
      base: option('--base'),
      all: argv.includes('--all'),
      migration: option('--migration'),
      databaseUrl: option('--database-url'),
    });

    if (reports.length === 0) {
      console.log('[zero-downtime] No changed migrations to verify.');
      return 0;
    }

    for (const report of reports) console.log(formatRiskReport(report));
    return reports.every((report) => report.passed) ? 0 : 1;
  } catch (error) {
    console.error(`[zero-downtime] ${error instanceof Error ? error.message : String(error)}`);
    return 2;
  }
}

const isEntrypoint = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isEntrypoint) {
  main().then((code) => { process.exitCode = code; });
}
