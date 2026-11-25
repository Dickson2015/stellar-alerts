/**
 * Stellar claimable balance claim-predicate evaluation.
 *
 * A claim predicate is an upper-bound time lock: it says *until when* a claimant
 * may claim, not *from when*. Horizon serializes predicates in its own JSON
 * shape (`unconditional`, `abs_before`, `rel_before`, `not`, `and`, `or`), where
 * `abs_before` is an ISO-8601 timestamp and `rel_before` is a number of seconds
 * relative to the ledger entry's creation time.
 *
 * Because predicates can be nested under `not`, a balance can genuinely become
 * claimable *after* a bound (e.g. `not(abs_before(X))`), and an `and`/`or` over
 * several bounds produces an arbitrary set of windows. Instead of guessing, the
 * evaluator collects every timestamp at which the predicate can change value
 * (each `abs_before`/`rel_before` boundary, plus one millisecond after it) and
 * evaluates the tree at those points. That yields the exact earliest claimable
 * time and the exact expiry time to the millisecond.
 */

export type ClaimPredicate =
  | { unconditional: true }
  | { abs_before: string }
  /** Relative offset in seconds (Horizon sends a string; numbers are accepted). */
  | { rel_before: string | number }
  | { not: ClaimPredicate }
  | { and: ClaimPredicate[] }
  | { or: ClaimPredicate[] };

export interface ClaimWindow {
  /** Whether the predicate is satisfied at the requested evaluation time. */
  claimableNow: boolean;
  /** Earliest time at or after `createdAt` when the predicate becomes satisfied. */
  becomesClaimableAt: Date | null;
  /** First time after `becomesClaimableAt` when the predicate stops being satisfied. */
  expiresAt: Date | null;
  /** True when the predicate can never be satisfied after `createdAt`. */
  neverClaimable: boolean;
}

function toMillis(value: Date | string | number): number {
  if (value instanceof Date) return value.getTime();
  if (typeof value === 'number') return value;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? NaN : parsed;
}

function isPredicate(value: unknown): value is ClaimPredicate {
  return typeof value === 'object' && value !== null;
}

/** Returns whether `predicate` is structurally valid (unknown keys are ignored). */
export function isValidClaimPredicate(predicate: unknown): predicate is ClaimPredicate {
  if (!isPredicate(predicate)) return false;

  if ('unconditional' in predicate) return predicate.unconditional === true;
  if ('abs_before' in predicate) return !Number.isNaN(Date.parse(String(predicate.abs_before)));
  if ('rel_before' in predicate) {
    const rel = Number(predicate.rel_before);
    return Number.isFinite(rel) && rel >= 0;
  }
  if ('not' in predicate) return isValidClaimPredicate(predicate.not);
  if ('and' in predicate) {
    return Array.isArray(predicate.and) && predicate.and.length > 0 && predicate.and.every(isValidClaimPredicate);
  }
  if ('or' in predicate) {
    return Array.isArray(predicate.or) && predicate.or.length > 0 && predicate.or.every(isValidClaimPredicate);
  }
  return false;
}

/**
 * Evaluates a predicate at a point in time.
 *
 * `createdAt` anchors `rel_before`; it defaults to `at` so standalone
 * evaluation of a relative predicate behaves as "claimable for the next N
 * seconds" rather than throwing.
 */
export function evaluateClaimPredicate(
  predicate: ClaimPredicate,
  at: Date | string | number,
  createdAt?: Date | string | number,
): boolean {
  const now = toMillis(at);
  if (Number.isNaN(now)) return false;
  const created = createdAt === undefined ? now : toMillis(createdAt);
  if (Number.isNaN(created)) return false;

  if ('unconditional' in predicate) return predicate.unconditional === true;

  if ('abs_before' in predicate) {
    const deadline = Date.parse(predicate.abs_before);
    if (Number.isNaN(deadline)) return false;
    return now < deadline;
  }

  if ('rel_before' in predicate) {
    const seconds = Number(predicate.rel_before);
    if (!Number.isFinite(seconds) || seconds < 0) return false;
    return now < created + seconds * 1000;
  }

  if ('not' in predicate) return !evaluateClaimPredicate(predicate.not, now, created);

  if ('and' in predicate) {
    return predicate.and.every((child) => evaluateClaimPredicate(child, now, created));
  }

  if ('or' in predicate) {
    return predicate.or.some((child) => evaluateClaimPredicate(child, now, created));
  }

  return false;
}

/**
 * Collects every instant at which the predicate's truth value can change.
 * The predicate is constant between consecutive boundaries, so evaluating at
 * the boundaries (and 1ms after each, since `abs_before`/`rel_before` are
 * exclusive) is sufficient to locate the exact claim window.
 */
function collectBoundaries(
  predicate: ClaimPredicate,
  createdAt: number,
  out: Set<number>,
): void {
  if ('abs_before' in predicate) {
    const deadline = Date.parse(predicate.abs_before);
    if (!Number.isNaN(deadline)) out.add(deadline);
    return;
  }
  if ('rel_before' in predicate) {
    const seconds = Number(predicate.rel_before);
    if (Number.isFinite(seconds) && seconds >= 0) out.add(createdAt + seconds * 1000);
    return;
  }
  if ('not' in predicate) {
    collectBoundaries(predicate.not, createdAt, out);
    return;
  }
  if ('and' in predicate) {
    for (const child of predicate.and) collectBoundaries(child, createdAt, out);
    return;
  }
  if ('or' in predicate) {
    for (const child of predicate.or) collectBoundaries(child, createdAt, out);
  }
}

/**
 * Computes the exact claim window for a predicate, relative to the balance's
 * creation time.
 */
export function computeClaimWindow(
  predicate: ClaimPredicate,
  createdAt: Date | string | number,
  now: Date | string | number = Date.now(),
): ClaimWindow {
  const created = toMillis(createdAt);
  const nowMs = toMillis(now);

  if (Number.isNaN(created)) {
    return { claimableNow: false, becomesClaimableAt: null, expiresAt: null, neverClaimable: true };
  }

  const boundaries = new Set<number>([created]);
  collectBoundaries(predicate, created, boundaries);

  // 1ms after each boundary captures the "just past an exclusive upper bound" state.
  const candidates = new Set<number>();
  for (const boundary of boundaries) {
    if (boundary >= created) candidates.add(boundary);
    candidates.add(boundary + 1);
  }
  const ordered = Array.from(candidates).sort((a, b) => a - b);

  let becomesClaimableAt: number | null = null;
  for (const candidate of ordered) {
    if (evaluateClaimPredicate(predicate, candidate, created)) {
      becomesClaimableAt = candidate;
      break;
    }
  }

  if (becomesClaimableAt === null) {
    return {
      claimableNow: false,
      becomesClaimableAt: null,
      expiresAt: null,
      neverClaimable: true,
    };
  }

  let expiresAt: number | null = null;
  for (const candidate of ordered) {
    if (candidate > becomesClaimableAt && !evaluateClaimPredicate(predicate, candidate, created)) {
      expiresAt = candidate;
      break;
    }
  }

  return {
    claimableNow: Number.isNaN(nowMs) ? false : evaluateClaimPredicate(predicate, nowMs, created),
    becomesClaimableAt: new Date(becomesClaimableAt),
    expiresAt: expiresAt === null ? null : new Date(expiresAt),
    neverClaimable: false,
  };
}

/**
 * Normalizes the various shapes a predicate can arrive in — Horizon JSON,
 * already-normalized predicates, or the legacy `{ absBeforeLedger: N }`
 * internal shape — into a {@link ClaimPredicate}.
 *
 * Legacy ledger-based predicates cannot be converted to a timestamp without a
 * ledger clock, so callers that need exact windows should pass a
 * `ledgerToTime` function. Without one the legacy bound is treated as
 * "unconditional" and surfaced through `legacy` for the caller to warn about.
 */
export function normalizeClaimPredicate(
  raw: unknown,
  options: { ledgerToTime?: (ledger: number) => Date | null } = {},
): { predicate: ClaimPredicate; legacy: boolean } {
  if (isValidClaimPredicate(raw)) {
    return { predicate: raw, legacy: false };
  }

  if (isPredicate(raw) && 'absBeforeLedger' in raw) {
    const ledger = Number((raw as { absBeforeLedger?: unknown }).absBeforeLedger);
    const converted = Number.isFinite(ledger) ? options.ledgerToTime?.(ledger) : null;
    if (converted && !Number.isNaN(converted.getTime())) {
      return { predicate: { abs_before: converted.toISOString() }, legacy: true };
    }
    return { predicate: { unconditional: true }, legacy: true };
  }

  return { predicate: { unconditional: true }, legacy: false };
}
