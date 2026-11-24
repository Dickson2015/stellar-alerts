import { PrismaClient } from '../../generated/prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { env } from '../config/env';
import { resolvePoolConfig, PoolConfig } from './db-pool';
import {
  MUTATION_OPERATIONS,
  configureCausalRouter,
  createCausalReadProxy,
  getCausalContext,
  getCausalRouter,
  recordMutationForContext,
} from './prisma-causal-router';

export const DEFAULT_PRISMA_CONNECTION_LIMIT = 50;
export const DEFAULT_PRISMA_POOL_TIMEOUT_SECONDS = 15;

export interface DatabasePoolUrlOptions {
  connectionLimit?: number;
  poolTimeout?: number;
  idleTimeout?: number;
}

/**
 * Ensures `connection_limit` and `pool_timeout` are present in a PostgreSQL
 * connection URL so the Prisma connection pool can absorb high-concurrency
 * watcher bursts (50+ concurrent queries) without exhausting connections.
 * Existing query parameters on `databaseUrl` are preserved unless explicitly
 * overridden in `options`.
 */
export function buildPooledDatabaseUrl(
  databaseUrl: string,
  options: DatabasePoolUrlOptions = {}
): string {
  const url = new URL(databaseUrl);
  const params = url.searchParams;

  if (options.connectionLimit !== undefined) {
    params.set('connection_limit', String(options.connectionLimit));
  } else if (!params.has('connection_limit')) {
    params.set('connection_limit', String(DEFAULT_PRISMA_CONNECTION_LIMIT));
  }

  if (options.poolTimeout !== undefined) {
    params.set('pool_timeout', String(options.poolTimeout));
  } else if (!params.has('pool_timeout')) {
    params.set('pool_timeout', String(DEFAULT_PRISMA_POOL_TIMEOUT_SECONDS));
  }

  if (options.idleTimeout !== undefined) {
    params.set('idle_timeout', String(options.idleTimeout));
  }

  return url.toString();
}

let primaryPoolConfig: PoolConfig | null = null;
let replicaPoolConfig: PoolConfig | null = null;

function createClient(databaseUrl: string, label: string) {
  const pooledUrl = buildPooledDatabaseUrl(databaseUrl);
  const config = resolvePoolConfig(pooledUrl);
  if (label.startsWith('primary')) {
    primaryPoolConfig = config;
  } else if (label === 'replica') {
    replicaPoolConfig = config;
  }
  console.log(
    `[Prisma] ${label} pool: max=${config.max} connections, acquire timeout=${config.connectionTimeoutMillis}ms, idle timeout=${config.idleTimeoutMillis}ms`
  );

  return new PrismaClient({ adapter: new PrismaPg(config) });
}

export function getPrimaryPoolConfig(): PoolConfig | null {
  return primaryPoolConfig;
}

export function getReplicaPoolConfig(): PoolConfig | null {
  return replicaPoolConfig;
}

const primaryUrl = env.DATABASE_URL || process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/stellar_alerts';
const replicaUrl = env.READ_REPLICA_URL || process.env.READ_REPLICA_URL;

let primaryClient = createClient(primaryUrl, 'primary');

/**
 * Wraps every mutation delegate so a successful write records the primary WAL
 * LSN for the current user's RYOW watermark. Failures (Redis unavailable, LSN
 * probe failure) must never turn a successful database write into a failed
 * API request, so watermark recording is best-effort and logged.
 */
async function recordWatermarkAfterMutation(result: unknown): Promise<unknown> {
  try {
    await recordMutationForContext();
  } catch (error: any) {
    console.warn(`[RYOW] Failed to record mutation watermark: ${error?.message || error}`);
  }
  return result;
}

function wrapMutationDelegate(delegate: object): object {
  return new Proxy(delegate, {
    get(target, method, receiver) {
      const value = Reflect.get(target, method, receiver);
      if (typeof value !== 'function' || !MUTATION_OPERATIONS.has(String(method))) {
        return typeof value === 'function' ? value.bind(target) : value;
      }
      return async (...args: unknown[]) => {
        const result = await (value as (...args: unknown[]) => unknown).apply(target, args);
        return recordWatermarkAfterMutation(result);
      };
    },
  });
}

export const prisma: PrismaClient = new Proxy({} as PrismaClient, {
  get(_target, prop) {
    const value = (primaryClient as unknown as Record<string | symbol, unknown>)[prop];
    if (typeof value === 'function') {
      // `$transaction` receives its own client, so delegate-level wrapping does
      // not observe writes made inside it. Record once on completion instead.
      if (prop === '$transaction') {
        return async (...args: unknown[]) =>
          recordWatermarkAfterMutation(
            await (value as (...args: unknown[]) => unknown).apply(primaryClient, args),
          );
      }
      return (value as (...args: unknown[]) => unknown).bind(primaryClient);
    }
    if (value && typeof value === 'object') {
      return wrapMutationDelegate(value as object);
    }
    return value;
  },
});

/**
 * Client for read-only queries. Points at READ_REPLICA_URL when a read
 * replica is configured and falls back to the primary otherwise, so callers can
 * use it unconditionally.
 */
export const prismaRead = replicaUrl ? createClient(replicaUrl, 'replica') : prisma;
export const replicaPrisma = prismaRead;

// The LSN probes live here so they follow the primary client across DR
// promotions; the causal router itself stays free of a prisma import cycle.
configureCausalRouter({
  getPrimaryLsn: async () => {
    const rows = await primaryClient.$queryRaw<Array<{ lsn: string }>>`
      SELECT pg_current_wal_lsn()::text AS lsn
    `;
    return rows[0]?.lsn ?? '';
  },
  getReplicaLsn: async () => {
    // With no configured replica the "replica" is the primary itself, which
    // is by definition caught up with its own WAL.
    if (!replicaUrl) {
      const rows = await primaryClient.$queryRaw<Array<{ lsn: string }>>`
        SELECT pg_current_wal_lsn()::text AS lsn
      `;
      return rows[0]?.lsn ?? '';
    }
    const rows = await prismaRead.$queryRaw<Array<{ lsn: string }>>`
      SELECT pg_last_wal_replay_lsn()::text AS lsn
    `;
    return rows[0]?.lsn ?? '';
  },
});

export type DatabaseTarget = 'PRIMARY' | 'REPLICA';

export let activeReadTarget: DatabaseTarget = 'REPLICA';

export function setReadTarget(target: DatabaseTarget): void {
  activeReadTarget = target;
  console.log(`[DB Pool Engine] 🔀 Read traffic target updated to: ${target}`);
}

export function getReadTarget(): DatabaseTarget {
  return activeReadTarget;
}

export function getReadClient() {
  const client = activeReadTarget === 'PRIMARY' ? prisma : prismaRead;
  const context = getCausalContext();
  if (client === prisma || !context?.userId) return client;
  return createCausalReadProxy(context.userId, { primary: prisma, replica: client }, getCausalRouter());
}

/**
 * Explicit form of {@link getReadClient} for jobs that know the user but do
 * not run inside a request's causal context.
 */
export function getCausalReadClient(userId: string) {
  if (activeReadTarget === 'PRIMARY') return prisma;
  return createCausalReadProxy(userId, { primary: prisma, replica: prismaRead }, getCausalRouter());
}

export async function switchDatabaseUrl(newUrl: string): Promise<void> {
  console.log(`[Prisma] Switching database URL to: ${newUrl}`);
  process.env.DATABASE_URL = newUrl;
  setReadTarget('PRIMARY');

  try {
    await primaryClient.$disconnect();
  } catch {
    // Pool may not be connected during DR drills or unit tests.
  }

  primaryClient = createClient(newUrl, 'primary-promoted');

  if (process.env.VITEST !== 'true') {
    await primaryClient.$connect();
  }
}

export async function connectWithRetry() {
  await prisma.$connect();
}

/**
 * Executes a batch of watcher queries concurrently against the read client
 * (read replica when configured, primary otherwise), bounded by the configured
 * connection pool limit so bursts of 50+ concurrent watcher queries never
 * exhaust PostgreSQL connections.
 */
export async function executeConcurrentWatcherQueries<T>(
  tasks: Array<(client: PrismaClient) => Promise<T>>,
  maxConcurrency: number = primaryPoolConfig?.max ?? DEFAULT_PRISMA_CONNECTION_LIMIT
): Promise<T[]> {
  if (tasks.length === 0) return [];
  const limit = Math.max(1, maxConcurrency);
  const results = new Array<T>(tasks.length);
  let nextIndex = 0;
  const client = getReadClient();

  async function worker() {
    while (nextIndex < tasks.length) {
      const idx = nextIndex++;
      results[idx] = await tasks[idx](client);
    }
  }

  const workerCount = Math.min(limit, tasks.length);
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return results;
}
