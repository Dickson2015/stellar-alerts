# Fix reliability & Stellar monitoring gaps: adaptive worker scaling, tamper-evident audit chain, claimable-balance predicates, path-payment decomposition

Closes #912
Closes #913
Closes #914
Closes #915

Upstream: `stellar-alerts-labs/stellar-alerts`

---

## 📌 Overview

This PR implements four high-complexity Stellar Wave items. Three of them had partially-landed placeholder code in the tree that did not actually satisfy its own acceptance criteria (a worker scaler reading non-existent Node APIs, a claimable-balance evaluator that inverted `abs_before`, and a path-payment “decomposer” that never decoded XDR). Those implementations are replaced with correct, tested versions rather than layered over. The payment checksum chain (#914) was already correctly implemented; this PR adds the missing audit/verification tooling and a streaming verifier for large chains.

| Issue | Area | Result |
| --- | --- | --- |
| #915 | Backend / performance | Real event-loop + heap + Redis-backlog metrics, bounded scaling controller, Prometheus gauge, dispatcher integration, unit tests |
| #914 | Stellar / security | Streaming checksum-chain verifier + daily Merkle root audit for 100k+ records, exact tamper index |
| #913 | Stellar / feature | Full claim-predicate AST evaluator with exact claim windows, lifecycle notifications, Horizon fetcher, tests |
| #912 | Stellar / analytics | Real XDR decoding, ordered hop extraction, effective price/arbitrage vs spot, alert visualization metadata, 4-hop XDR test |

---

## #915 — Dynamic adaptive BullMQ worker auto-scaler

### What was wrong

`apps/api/src/lib/worker-scaler.ts` read `global.eventLoopUtilization` and `global.process.memory`, neither of which exists, so both metrics were permanently `0`. Queue depth was read from a hard-coded `bull:default` list instead of the actual lane queues. Nothing ever invoked the scaler, and no metric was exported.

### Changes

- **Metrics collection**
  - Event-loop delay now comes from `perf_hooks.monitorEventLoopDelay()`; each read resets the histogram and returns an interval mean in milliseconds (no lifetime-drift).
  - Heap pressure uses `process.memoryUsage()` (`heapUsed / heapTotal`).
  - Backlog sums `LLEN` across a configurable list of BullMQ `wait` keys, and a single unavailable key no longer zeroes the total.
- **Scaling controller**
  - Scale up when backlog > 500 **and** lag < 20 ms.
  - Scale down when lag > 50 ms **or** heap > 80%.
  - Gentle step-down when the queue is shallow and the event loop is healthy, so the pool does not stay overprovisioned after a burst.
  - Bounded to `[5, 50]`, 30 s cooldown between decisions, `start()/stop()` loop (unref'd timer, histogram released on stop).
- **Prometheus**
  - New `stellar_alerts_worker_concurrency{worker="…"}` gauge in `prometheus.service.ts`, updated on every metrics collection and every applied decision.
- **Dispatcher integration**
  - `DispatcherWorker.start()` attaches a scaler over the four lane `wait` queues (`webhook-dispatch-{critical,high,standard,bulk}`). On each scale event the new total is redistributed across lanes in proportion to `QUEUE_LANE_CONFIGS`, mutating `worker.concurrency`; the scaler is stopped by the existing Redis cleanup task.
- **Tests** (`apps/api/src/lib/__tests__/worker-scaler.test.ts`)
  - Simulated load/latency/memory inputs for up-scale, both down-scale paths, min/max bounds, cooldown, multi-queue summation with a failing Redis key, and real default providers.

### Acceptance criteria

- [x] Scales up at backlog > 500 and event-loop lag < 20 ms
- [x] Scales down at lag > 50 ms or memory pressure > 80%
- [x] Exposes current worker concurrency to Prometheus (`stellar_alerts_worker_concurrency`)
- [x] Unit tests for the scaling controller with simulated metrics

---

## #914 — Ledger ingestion checksum chain for tamper-proof audit logging

### Existing state

`services/checksumChain.service.ts` already appends `PaymentChecksum` rows with `Hash_N = SHA256(Hash_{N-1} || payloadHash_N)` in a Serializable transaction, wires ingestion in `watcher.worker.ts`, and rolls up daily Merkle roots. What was missing was the independent verification path required by the issue.

### Changes

- **`verifyChainInBatches()`** — streaming verifier that pages through the chain in `sequence` order (`batchSize`, default 5,000; optional `maxRecords`) so a 100k+ chain is audited in bounded memory. It recomputes both `previousHash` linkage and each row's `chainHash`, returning the **exact sequence number** of the first broken link plus progress callbacks.
- **`verifyDailyChecksumRoots()`** — recomputes every stored daily Merkle root from its day's checksum rows and compares leaf count + root. This anchors the chain head, catching newly-deleted tail rows that a forward-only walk cannot see.
- **`apps/api/src/scripts/verify-checksum-chain.ts`** — CLI audit (`npm run verify:checksum-chain`, flags `--batch-size=`, `--max-records=`, `--json`, `--skip-daily-roots`). Exit code `0` intact, `1` tampering detected, `2` verification error.
- `sequence` gaps are reported separately as an operator signal (autoincrement can skip after a rolled-back insert) and are not treated as tampering on their own.
- Tests cover multi-page walking and tamper detection on a later page.

### Acceptance criteria

- [x] Deterministic cryptographic checksum chain for recorded payments (pre-existing, now independently verifiable)
- [x] Verification tool audits an unbroken sequence across 100,000+ records (paginated; no full-table load)
- [x] Missing/modified records are reported with the exact sequence index of the tamper point; tail deletions are caught by the daily Merkle root check
- [x] Unit tests for checksum generation and tamper detection

---

## #913 — Stellar claimable balance watcher with time-lock evaluator

### What was wrong

The previous evaluator mapped `abs_before` to “claimable **after** this ledger”, which is backwards — `abs_before`/`rel_before` are exclusive **upper bounds**. It also used ledger numbers instead of Stellar's timestamp predicates, never handled a balance that becomes claimable after a `not(...)`, ignored `or`/`not` deadlines when computing expiry, and emitted notifications for every claimant unconditionally.

### Changes

- **New shared module `packages/shared/src/utils/predicates.ts`**
  - Horizon predicate AST: `unconditional`, `abs_before` (ISO-8601), `rel_before` (seconds since the entry was created), `not`, `and`, `or`.
  - `evaluateClaimPredicate()` with correct exclusive-bound semantics and `createdAt` anchoring for relative bounds.
  - `computeClaimWindow()` collects every boundary in the tree (plus 1 ms after each, since bounds are exclusive) and evaluates at those points, yielding the **exact** earliest claimable instant and expiry instant — including delayed windows from `not(abs_before(...))` and multi-bound `and`/`or` trees.
  - `normalizeClaimPredicate()` handles Horizon JSON, already-normalized predicates, and legacy `{ absBeforeLedger }` input (converted via an optional ledger clock, otherwise surfaced rather than silently mis-evaluated).
- **Worker rewrite (`apps/api/src/workers/claimable-balance.worker.ts`)**
  - Emits `CREATED`, `NOW_CLAIMABLE`, `EXPIRING_SOON` (default 24 h window), `EXPIRED`, and `NEVER_CLAIMABLE` alerts with ISO `claimableAt` / `expiresAt`.
  - `pollClaimableBalances()` polls injected Horizon fetchers per monitored claimant, isolates per-claimant fetch failures, and dispatches through an injectable notifier.
  - Production entrypoint reads `CLAIMABLE_BALANCE_MONITORED_ADDRESSES` (comma-separated) and lazily builds a Horizon fetcher, so unit tests never load env/Horizon.
- **Horizon support** — `stellar.getClaimableBalancesWithPredicates()` preserves each claimant's raw predicate and creation time, instead of flattening predicates away.
- `ClaimableBalanceWatcher` service is now a thin stateful wrapper over the pure engine, preserving its existing call sites.
- Tests cover unconditional, absolute, relative, nested AND/OR, delayed `not(...)` windows, never-claimable trees, alert lifecycle, monitoring filters, fetch isolation, and notification dispatch.

### Acceptance criteria

- [x] Recursively evaluates predicate trees (unconditional, rel_before, abs_before)
- [x] Calculates the exact date/time the balance becomes claimable or expires
- [x] Emits a notification when a balance is created or ready for claiming (plus expiry warnings)
- [x] Unit tests for nested AND/OR predicate structures

---

## #912 — Path payment strict send/receive route decomposition

### What was wrong

`modules/stellar/path-payment.service.ts` did not decode XDR at all. It invented hops from array indices, assigned a constant `0.5%` slippage, hard-coded a spot price of `1.0`, and built a Merkle proof using the tree root as the leaf hash.

### Changes

- **Real XDR decoding** — `decodePathPaymentOperation()` parses base64 operation XDR with `stellar-sdk`, supporting `pathPaymentStrictSend` and `pathPaymentStrictReceive`, extracting send/dest assets, ordered path, exact/min/max amounts, and the operation source when present. Non-path-payment operations are rejected.
- **Ordered hop extraction** — `buildPathPaymentHops()` produces `sendAsset → path[0] → … → destAsset` with per-hop `amountIn`/`amountOut`/`price`.
  - First-hop input and last-hop output come from executed operation data.
  - Intermediate amounts are attached only when real trade data (`hopAmounts`) is supplied — no fabricated proportional splits. A length mismatch is rejected.
- **Pricing & arbitrage** — `decomposePathPayment()` computes the effective execution price (`dest / source`), compares it to an injected spot reference, and reports arbitrage in basis points with a configurable threshold (default 50 bps). Missing inputs yield `null`, never a made-up number.
- **Alert metadata** — `buildPathPaymentAlertMetadata()` attaches hop list plus a node/edge `pathVisualization` graph to alert payloads.
- Removed the incorrect Merkle-proof helper (unused and cryptographically wrong).
- Tests build real 4-hop strict-send and strict-receive XDR envelopes and assert hop order, realized amounts/prices, pricing/arbitrage, visualization metadata, and invalid-input handling.

### Acceptance criteria

- [x] Decomposes path payments into an ordered sequence of intermediate asset hops
- [x] Calculates effective execution price and compares it against a spot reference
- [x] Attaches conversion-path visualization metadata to alert payloads
- [x] Unit test with a 4-hop path payment operation XDR verifying hop extraction

---

## 🗂 Files changed

**Core**
- `apps/api/src/lib/worker-scaler.ts` — rewritten metrics + controller + lifecycle
- `apps/api/src/modules/metrics/prometheus.service.ts` — worker concurrency gauge
- `apps/api/src/workers/dispatcher.worker.ts` — scaler attachment and lane redistribution
- `apps/api/src/services/checksumChain.service.ts` — streaming verifier + daily-root audit
- `apps/api/src/scripts/verify-checksum-chain.ts` — new CLI audit
- `packages/shared/src/utils/predicates.ts` — new predicate engine
- `packages/shared/src/index.ts` — export predicate engine
- `apps/api/src/workers/claimable-balance.worker.ts` — rewritten evaluator/notifier
- `apps/api/src/services/claimableBalanceWatcher.ts` — wrapper over shared engine
- `apps/api/src/lib/stellar.ts` — predicate-preserving claimable-balance fetch
- `apps/api/src/modules/stellar/path-payment.service.ts` — rewritten decomposer

**Tests**
- `apps/api/src/lib/__tests__/worker-scaler.test.ts` (new, 7 tests)
- `apps/api/src/workers/__tests__/claimable-balance.worker.test.ts` (new, 12 tests)
- `apps/api/src/modules/stellar/__tests__/path-payment.service.test.ts` (new, 8 tests)
- `apps/api/src/services/__tests__/checksumChain.service.test.ts` (+2 pagination/tamper tests)
- `apps/api/src/services/__tests__/watchers.test.ts` (updated to new predicate semantics)

**Scripts**
- `package.json` / `apps/api/package.json` — `verify:checksum-chain`

---

## 🧪 Verification

Run:

```bash
npm ci
npm run typecheck --workspace=api
npx vitest run \
  src/lib/__tests__/worker-scaler.test.ts \
  src/workers/__tests__/claimable-balance.worker.test.ts \
  src/modules/stellar/__tests__/path-payment.service.test.ts \
  src/services/__tests__/checksumChain.service.test.ts \
  src/services/__tests__/watchers.test.ts \
  src/modules/metrics/prometheus.service.test.ts \
  src/workers/__tests__/path-payment-slippage-watcher.test.ts
```

Result on this branch: **7 test files passed, 68 tests passed**.

Typecheck for the touched files is clean. `apps/api` still reports 16 pre-existing errors in unrelated files (`modules/stellar/anchor-watcher.service.ts` and `workers/archival.worker.ts`) caused by the checked-in generated Prisma client being out of date with `schema.prisma`; they are untouched by this PR and should be resolved by regenerating the client.

The checksum-chain verifier is exercised through paginated unit tests with mocked storage; it was **not** run against a live 100k-row production database in this environment.

---

## ⚙️ Operational notes

- New metric: `stellar_alerts_worker_concurrency{worker="webhook-dispatcher"}`. Scaler runs every 15 s once `DispatcherWorker.start()` is called.
- Claimable-balance worker enablement: set `CLAIMABLE_BALANCE_MONITORED_ADDRESSES` to a comma-separated list of claimant public keys and run `apps/api/src/workers/claimable-balance.worker.ts`. Per-hop trade data is required for intermediate amounts in path-payment alerts; without it, only the first input and final output are populated.
- Audit job: `npm run verify:checksum-chain --workspace=api` (or `npx tsx src/scripts/verify-checksum-chain.ts`) with `DATABASE_URL` set.

## 🚫 Out of scope

- Regenerating the stale Prisma client for the unrelated `anchor-watcher` / `archival` errors.
- Persisting claimable-balance alert subscriptions or adding new notification channels; the worker dispatches through the injected notifier used by existing watchers.
