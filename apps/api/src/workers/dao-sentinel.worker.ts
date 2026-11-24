import { prisma } from '../lib/prisma';
import { createLogger } from '../lib/logger';
import { fetchContractEvents, getSorobanLatestLedger } from '../lib/soroban';
import {
  DaoGovernanceSentinel,
  type DaoAlert,
  type DaoEvent,
  type VotingPowerLookup,
} from '../modules/soroban/dao-sentinel.service';
import { registerSupervisorHeartbeat } from './supervisor';

const log = createLogger({ module: 'DaoSentinelWorker' });

const POLL_INTERVAL_MS = 30_000;
const DEFAULT_LOOKBACK_LEDGERS = 100;
const DAO_TOPICS = ['proposal_created', 'proposal_queued', 'vote_cast'] as const;

export type DaoNotifier = (alert: DaoAlert) => Promise<void> | void;

export const defaultDaoNotifier: DaoNotifier = (alert) => {
  log.warn(
    { type: alert.type, severity: alert.severity, proposalId: alert.proposalId, txHash: alert.txHash },
    alert.summary,
  );
};

function recordOf(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
}

function topicName(topic: unknown): string {
  if (typeof topic === 'string') return topic.toLowerCase();
  const sym = recordOf(topic).symbol;
  return typeof sym === 'string' ? sym.toLowerCase() : '';
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' || typeof value === 'number' || typeof value === 'bigint'
    ? String(value)
    : undefined;
}

function toMs(value: unknown): number | undefined {
  if (typeof value === 'number') return value < 1e12 ? value * 1000 : value;
  if (typeof value === 'string') {
    const asDate = Date.parse(value);
    if (!Number.isNaN(asDate)) return asDate;
    const asNumber = Number(value);
    if (!Number.isNaN(asNumber)) return asNumber < 1e12 ? asNumber * 1000 : asNumber;
  }
  return undefined;
}

/**
 * Normalizes a decoded Soroban governance event into a DaoEvent.
 * Returns null for unrelated events or events missing required fields.
 */
export function parseDaoEvent(raw: unknown, fallbackContractId: string): DaoEvent | null {
  const event = recordOf(raw);
  const topics = Array.isArray(event.topic) ? event.topic.map(topicName) : [];
  const kind = DAO_TOPICS.find((name) => topics.includes(name));
  if (!kind) return null;

  const data = recordOf(event.value ?? event.data);
  const proposalId = str(data.proposalId ?? data.proposal_id ?? data.id);
  const txHash = str(event.txHash ?? event.transactionHash);
  const ledgerSeq = Number(event.ledgerSeq ?? event.ledger);
  const timestampMs = toMs(event.ledgerClosedAt ?? event.timestamp) ?? Date.now();
  if (!proposalId || !txHash || !Number.isFinite(ledgerSeq)) return null;

  const base = {
    contractId: str(event.contractId) ?? fallbackContractId,
    proposalId,
    txHash,
    ledgerSeq,
    timestampMs,
  };

  if (kind === 'proposal_queued') {
    return { ...base, kind, executableAtMs: toMs(data.eta ?? data.executableAt ?? data.executable_at) };
  }

  if (kind === 'vote_cast') {
    const voter = str(data.voter);
    const weight = str(data.weight ?? data.votes ?? data.power);
    if (!voter || weight === undefined) return null;
    return { ...base, kind, voter, support: data.support === true || data.support === 1 || data.support === 'for', weight };
  }

  const votingStartsMs = toMs(data.startTime ?? data.start_time ?? data.start);
  const votingEndsMs = toMs(data.endTime ?? data.end_time ?? data.end);
  const totalVotingPower = str(data.totalVotingPower ?? data.total_voting_power ?? data.totalSupply);
  if (votingStartsMs === undefined || votingEndsMs === undefined || totalVotingPower === undefined) return null;

  return {
    ...base,
    kind,
    proposer: str(data.proposer),
    title: str(data.title),
    votingStartsMs,
    votingEndsMs,
    quorum: str(data.quorum),
    totalVotingPower,
  };
}

export function getDaoContractIds(): string[] {
  return Array.from(
    new Set(
      (process.env.DAO_CONTRACT_IDS || '')
        .split(',')
        .map((id) => id.trim())
        .filter(Boolean),
    ),
  );
}

/** Feeds a batch of raw events to the sentinel in ledger order. */
export async function processDaoEventBatch(
  sentinel: DaoGovernanceSentinel,
  rawEvents: unknown[],
  contractId: string,
): Promise<DaoAlert[]> {
  const parsed = rawEvents
    .map((raw) => parseDaoEvent(raw, contractId))
    .filter((event): event is DaoEvent => event !== null)
    .sort((a, b) => a.ledgerSeq - b.ledgerSeq);

  const alerts: DaoAlert[] = [];
  for (const event of parsed) alerts.push(...(await sentinel.processEvent(event)));
  return alerts;
}

export async function runDaoSentinelPass(
  sentinel: DaoGovernanceSentinel,
  cursors: Map<string, number>,
): Promise<void> {
  const contractIds = getDaoContractIds();
  if (contractIds.length === 0) {
    const subscriptions = await prisma.sorobanContractSubscription.findMany({
      where: { isActive: true, topic: { in: [...DAO_TOPICS] } },
      select: { contractId: true },
    });
    for (const { contractId } of subscriptions) {
      if (!contractIds.includes(contractId)) contractIds.push(contractId);
    }
  }
  if (contractIds.length === 0) return;

  const latestLedger = await getSorobanLatestLedger();
  if (latestLedger === 0) {
    log.warn('Could not fetch latest Soroban ledger this pass, skipping');
    return;
  }

  for (const contractId of contractIds) {
    try {
      const startLedger = cursors.get(contractId) ?? Math.max(1, latestLedger - DEFAULT_LOOKBACK_LEDGERS);
      if (startLedger > latestLedger) continue;
      const events = await fetchContractEvents(contractId, startLedger);
      await processDaoEventBatch(sentinel, events, contractId);
      cursors.set(contractId, latestLedger + 1);
    } catch (err) {
      log.error({ contractId, err: err instanceof Error ? err.message : String(err) }, 'DAO sentinel pass failed');
    }
  }
}

export async function runDaoSentinelWorker(
  notify: DaoNotifier = defaultDaoNotifier,
  votingPower: VotingPowerLookup | null = null,
) {
  log.info('Starting Soroban DAO governance sentinel');
  const sentinel = new DaoGovernanceSentinel({}, votingPower);
  sentinel.subscribe(notify);
  const cursors = new Map<string, number>();

  const poll = async () => {
    try {
      await runDaoSentinelPass(sentinel, cursors);
    } catch (err) {
      log.error({ err: err instanceof Error ? err.message : String(err) }, 'DAO sentinel polling error');
    }
  };

  await poll();
  setInterval(poll, POLL_INTERVAL_MS);
}

if (require.main === module) {
  registerSupervisorHeartbeat();
  runDaoSentinelWorker();
}
