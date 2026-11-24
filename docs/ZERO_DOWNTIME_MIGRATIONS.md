# Zero-downtime migration gate

During a rolling Kubernetes deploy, version N and version N+1 of the API and
worker pods run against the same PostgreSQL database. A migration that is safe
for a single new process can break the old ones that are still serving traffic.

`scripts/check-zero-downtime-migrations.ts` statically analyzes the Prisma SQL
migrations changed in a pull request and fails the build when a statement
violates the expand-and-contract pattern. It also supports an optional dynamic
check against a database with real rows.

## What is blocked

| Code | Unsafe statement | Why | Expand-and-contract fix |
| --- | --- | --- | --- |
| `drop_table` | `DROP TABLE ...` | Old pods still query the table | Stop reads/writes, deploy, drop in a later release |
| `drop_column` | `ALTER TABLE ... DROP COLUMN ...` | Old pods still select the column | Stop reading it, deploy, drop in a later release |
| `rename_column` | `ALTER TABLE ... RENAME COLUMN ... TO ...` | A rename is a drop+add for old pods | Add the new column, dual-write/backfill, switch readers, drop the old column |
| `alter_column_type` | `ALTER COLUMN ... TYPE ...` | Old readers expect the old type | Add a typed column, backfill, switch readers, drop the old column |
| `add_column_not_null_without_default` | `ADD COLUMN ... NOT NULL` with no `DEFAULT` | Existing rows cannot satisfy the constraint | Add nullable with a default, backfill, then enforce `NOT NULL` |
| `set_not_null` | `ALTER COLUMN ... SET NOT NULL` | Fails while old rows contain NULLs | Backfill first, enforce `NOT NULL` in a later release |
| `create_index_without_concurrently` | `CREATE [UNIQUE] INDEX ...` | Takes a table lock during deploy | Use `CREATE INDEX CONCURRENTLY` outside a transaction block |

Every finding includes the migration file, line number, statement, affected
table/column, an explanation, and the remediation text above.

## Reviewed exceptions

If a breaking statement is genuinely required, put a pragma comment on the line
immediately before it. The justification is mandatory and is printed in the
report, so the exception stays auditable:

```sql
-- safe-migration: table is unused; verified by ops in ticket OPS-42
ALTER TABLE "LegacyQueue" DROP COLUMN "payload";
```

An acknowledged risk does not fail the gate.

## Running locally

```bash
# Only migrations changed against the base ref (default: origin/contribution)
npm run check:migrations:zero-downtime
npm run check:migrations:zero-downtime -- --base origin/main

# One migration, or the whole history (legacy migrations predate this gate)
npm run check:migrations:zero-downtime -- --migration 20261124000000_add_thing
npm run check:migrations:zero-downtime -- --all

# Also confirm NOT NULL additions against a populated database
npm run check:migrations:zero-downtime -- --database-url "$DATABASE_URL"
```

Exit codes: `0` = all changed migrations pass, `1` = unacknowledged blocking
risk found, `2` = the gate could not run (bad ref, missing file, DB error).

## CI

The `validate` job in `.github/workflows/ci.yml` runs the gate after the ops
script unit tests. Because it diffs against `origin/contribution`, the checkout
must keep full git history. Legacy migrations are intentionally not scanned by
default: several predate this policy and use non-concurrent index builds.
