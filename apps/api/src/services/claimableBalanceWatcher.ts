import type { ClaimPredicate } from '@stellar-alerts/shared';
import {
  processClaimableBalance,
  type ClaimableBalanceAlert,
  type ClaimableBalanceEntry as WorkerClaimableBalanceEntry,
} from '../workers/claimable-balance.worker';

export type { ClaimableBalanceAlert };

export interface Claimant {
  destination: string;
  predicate: ClaimPredicate;
}

export interface ClaimableBalanceEntry
  extends Omit<WorkerClaimableBalanceEntry, 'createdAt' | 'claimants'> {
  claimants: Claimant[];
  /** Ledger entry creation time; anchors `rel_before`. Defaults to now. */
  createdAt?: Date | string;
}

/**
 * Thin stateful wrapper around the pure predicate engine in
 * `workers/claimable-balance.worker.ts`. Keeps the monitored-address set for
 * callers (e.g. the trustline sentinel) that process balances one at a time.
 */
export class ClaimableBalanceWatcher {
  private monitoredAddresses: Set<string> = new Set();

  constructor(monitoredAddresses: string[] = []) {
    monitoredAddresses.forEach((addr) => this.monitoredAddresses.add(addr));
  }

  public addMonitoredAddress(address: string): void {
    this.monitoredAddresses.add(address);
  }

  public addMonitoredClaimant(claimant: Claimant): void {
    this.monitoredAddresses.add(claimant.destination);
  }

  public getMonitoredAddresses(): string[] {
    return Array.from(this.monitoredAddresses);
  }

  public processBalance(
    balance: ClaimableBalanceEntry,
    now: Date | string | number = Date.now(),
  ): ClaimableBalanceAlert[] {
    return processClaimableBalance(
      {
        ...balance,
        claimants: balance.claimants,
        createdAt: balance.createdAt ?? new Date(now),
      },
      this.monitoredAddresses,
      { now },
    );
  }
}
