/**
 * ClaimableBalanceWatcher (#913)
 *
 * Evaluates the full Stellar claim predicate AST (unconditional, abs_before,
 * rel_before — plus not/and/or composition), works out the exact instant a
 * balance becomes claimable and the exact instant it expires, and emits
 * alert payloads for claimants as those windows open and close.
 */

import { WorkerLifecycleManager } from '../lib/worker-lifecycle';
import {
  computeClaimWindow,
  evaluateClaimPredicate as evaluatePredicateAt,
  normalizeClaimPredicate,
  type ClaimPredicate,
  type ClaimWindow,
} from '@stellar-alerts/shared';

export { type ClaimPredicate, type ClaimWindow } from '@stellar-alerts/shared';

export const claimableBalanceLifecycle = new WorkerLifecycleManager({
  workerName: 'ClaimableBalanceWatcher',
  drainTimeoutMs: 10_000,
  maxInFlight: 5,
  autoRegisterSignals: true,
});

export type ClaimableBalanceAlertType = 'CREATED' | 'NOW_CLAIMABLE' | 'EXPIRING_SOON' | 'EXPIRED' | 'NEVER_CLAIMABLE';

export interface ClaimantEntry {
  /** Claimant Stellar account (G...) */
  destination: string;
  predicate: ClaimPredicate;
}

export interface ClaimableBalanceEntry {
  id: string;
  /** Asset in `CODE:ISSUER` form, or `XLM` for the native asset. */
  asset: string;
  amount: string;
  sponsor: string;
  claimants: ClaimantEntry[];
  /** Ledger entry creation time. Anchors `rel_before` predicates. */
  createdAt: Date | string;
  lastModifiedLedger?: number;
}

export interface ClaimableBalanceAlert {
  balanceId: string;
  claimantAddress: string;
  asset: string;
  amount: string;
  type: ClaimableBalanceAlertType;
  message: string;
  /** ISO timestamp when the balance becomes claimable, when it can be determined. */
  claimableAt?: string;
  /** ISO timestamp when the claim window closes, or null for no expiry. */
  expiresAt?: string | null;
}

export interface ClaimableBalanceProcessingOptions {
  /** Warn this long before expiry. Defaults to 24h. */
  expiringSoonWindowMs?: number;
  /** Reference time; defaults to now. */
  now?: Date | string | number;
  /** Optional ledger-clock mapping for legacy `absBeforeLedger` predicates. */
  ledgerToTime?: (ledger: number) => Date | null;
}

const DEFAULT_EXPIRING_SOON_WINDOW_MS = 24 * 60 * 60 * 1000;

function toDate(value: Date | string | number): Date {
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? new Date() : date;
}

/**
 * Evaluates a predicate at `at`. Kept as a thin, signature-compatible wrapper
 * around the shared evaluator so callers can evaluate a single claimant
 * without computing the whole window.
 */
export function evaluateClaimPredicate(
  predicate: ClaimPredicate,
  at: Date | string | number = Date.now(),
  createdAt: Date | string | number = at,
): {
  isClaimable: boolean;
  claimableAt?: Date;
  expiresAt?: Date | null;
  window: ClaimWindow;
} {
  const window = computeClaimWindow(predicate, createdAt, at);
  return {
    isClaimable: window.claimableNow,
    claimableAt: window.becomesClaimableAt ?? undefined,
    expiresAt: window.expiresAt,
    window,
  };
}

function alertBase(balance: ClaimableBalanceEntry, destination: string) {
  return {
    balanceId: balance.id,
    claimantAddress: destination,
    asset: balance.asset,
    amount: balance.amount,
  };
}

/**
 * Processes one claimable balance, returning an alert for every lifecycle
 * transition the balance is currently in for each monitored claimant.
 */
export function processClaimableBalance(
  balance: ClaimableBalanceEntry,
  monitoredAddresses: Set<string>,
  options: ClaimableBalanceProcessingOptions = {},
): ClaimableBalanceAlert[] {
  const now = toDate(options.now ?? Date.now());
  const createdAt = toDate(balance.createdAt);
  const soonWindow = options.expiringSoonWindowMs ?? DEFAULT_EXPIRING_SOON_WINDOW_MS;
  const alerts: ClaimableBalanceAlert[] = [];

  for (const claimant of balance.claimants) {
    if (monitoredAddresses.size > 0 && !monitoredAddresses.has(claimant.destination)) {
      continue;
    }

    const { predicate, legacy } = normalizeClaimPredicate(claimant.predicate, {
      ledgerToTime: options.ledgerToTime,
    });
    const window = computeClaimWindow(predicate, createdAt, now);
    const base = alertBase(balance, claimant.destination);
    const timing = {
      claimableAt: window.becomesClaimableAt?.toISOString(),
      expiresAt: window.expiresAt ? window.expiresAt.toISOString() : null,
    };

    alerts.push({
      ...base,
      type: 'CREATED',
      message: `New claimable balance ${balance.id} for ${balance.amount} ${balance.asset} is available to ${claimant.destination}`,
      ...timing,
    });

    if (legacy) {
      // A legacy ledger-number predicate can't be turned into a timestamp
      // without a ledger clock; the balance is still reported, never dropped.
      continue;
    }

    if (window.neverClaimable) {
      alerts.push({
        ...base,
        type: 'NEVER_CLAIMABLE',
        message: `Claimable balance ${balance.id} can no longer be claimed by ${claimant.destination}`,
        ...timing,
      });
      continue;
    }

    const expired = window.expiresAt !== null && now.getTime() >= window.expiresAt.getTime();
    if (expired) {
      alerts.push({
        ...base,
        type: 'EXPIRED',
        message: `Claimable balance ${balance.id} expired at ${window.expiresAt!.toISOString()} and can no longer be claimed by ${claimant.destination}`,
        ...timing,
      });
      continue;
    }

    if (window.claimableNow) {
      alerts.push({
        ...base,
        type: 'NOW_CLAIMABLE',
        message: `Claimable balance ${balance.id} is now claimable by ${claimant.destination}`,
        ...timing,
      });

      if (window.expiresAt) {
        const remainingMs = window.expiresAt.getTime() - now.getTime();
        if (remainingMs <= soonWindow) {
          alerts.push({
            ...base,
            type: 'EXPIRING_SOON',
            message: `Claimable balance ${balance.id} expires in ${Math.round(remainingMs / 60_000)} minutes (${window.expiresAt.toISOString()}) for ${claimant.destination}`,
            ...timing,
          });
        }
      }
    }
  }

  return alerts;
}

export type ClaimableBalanceNotifier = (alert: ClaimableBalanceAlert) => Promise<void> | void;

export const defaultClaimableBalanceNotifier: ClaimableBalanceNotifier = (alert) => {
  console.log(`[ClaimableBalanceWatcher] ${alert.type}: ${alert.message}`);
};

export type ClaimableBalanceFetcher = (claimant: string) => Promise<ClaimableBalanceEntry[]>;

export interface ClaimableBalanceWatcherOptions {
  monitoredAddresses: Iterable<string>;
  fetchBalances?: ClaimableBalanceFetcher;
  notify?: ClaimableBalanceNotifier;
  now?: () => Date;
}

/**
 * One polling pass: fetch every monitored claimant's balances, evaluate them,
 * and dispatch the resulting notifications.
 *
 * `fetchBalances` is injected so the Horizon client (and tests) stay outside
 * the predicate engine.
 */
export async function pollClaimableBalances(
  options: ClaimableBalanceWatcherOptions,
): Promise<ClaimableBalanceAlert[]> {
  const { fetchBalances, notify = defaultClaimableBalanceNotifier } = options;
  const monitored = new Set(Array.from(options.monitoredAddresses));
  if (!fetchBalances || monitored.size === 0) return [];

  const now = options.now ? options.now() : new Date();
  const allAlerts: ClaimableBalanceAlert[] = [];

  for (const claimant of monitored) {
    let balances: ClaimableBalanceEntry[];
    try {
      balances = await fetchBalances(claimant);
    } catch (err: any) {
      console.warn(
        `[ClaimableBalanceWatcher] Failed to fetch claimable balances for ${claimant}: ${err?.message ?? err}`,
      );
      continue;
    }

    for (const balance of balances) {
      const alerts = processClaimableBalance(balance, monitored, { now });
      for (const alert of alerts) {
        allAlerts.push(alert);
        await notify(alert);
      }
    }
  }

  return allAlerts;
}

export async function runClaimableBalanceWatcher(options: ClaimableBalanceWatcherOptions) {
  console.log('[ClaimableBalanceWatcher] 🚀 Starting claimable balance watcher...');
  return pollClaimableBalances(options);
}

/**
 * Builds the production fetcher: Horizon → worker entry shape. Imported
 * lazily so unit tests of the predicate engine never pull in env/Horizon.
 */
async function createHorizonFetcher(): Promise<ClaimableBalanceFetcher> {
  const { stellar } = await import('../lib/stellar');
  return async (claimant) => {
    const records = await stellar.getClaimableBalancesWithPredicates(claimant);
    return records.map((record) => ({
      id: record.id,
      asset: record.asset,
      amount: record.amount,
      sponsor: record.sponsor,
      createdAt: record.createdAt,
      lastModifiedLedger: record.lastModifiedLedger,
      claimants: record.claimants.map((c) => ({
        destination: c.destination,
        predicate: normalizeClaimPredicate(c.predicate).predicate,
      })),
    }));
  };
}

if (require.main === module) {
  const addresses = (process.env.CLAIMABLE_BALANCE_MONITORED_ADDRESSES ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);

  createHorizonFetcher().then((fetchBalances) =>
    runClaimableBalanceWatcher({ monitoredAddresses: addresses, fetchBalances }),
  );
}

export default {
  processClaimableBalance,
  pollClaimableBalances,
  evaluateClaimPredicate,
  runClaimableBalanceWatcher,
};
