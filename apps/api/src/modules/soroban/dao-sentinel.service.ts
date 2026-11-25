import { createLogger } from '../../lib/logger';

const logger = createLogger({ module: 'DaoGovernanceSentinel' });

const HOUR_MS = 60 * 60 * 1000;

export const DAO_SENTINEL_DEFAULTS = {
  /** Share of total voting power acquired inside the window that marks a flash vote. */
  flashVotePowerShare: 0.1,
  flashVoteWindowMs: 24 * HOUR_MS,
  /** A vote carrying at least this share of total power is reported as a whale vote. */
  whaleVoteShare: 0.05,
  /** Fraction of the voting period at the end that counts as "last minute". */
  finalPeriodShare: 0.1,
} as const;

export interface DaoSentinelConfig {
  flashVotePowerShare: number;
  flashVoteWindowMs: number;
  whaleVoteShare: number;
  finalPeriodShare: number;
}

export type DaoEvent =
  | ProposalCreatedEvent
  | ProposalQueuedEvent
  | VoteCastEvent;

interface DaoEventBase {
  contractId: string;
  proposalId: string;
  txHash: string;
  ledgerSeq: number;
  /** Ledger close time, epoch milliseconds. */
  timestampMs: number;
}

export interface ProposalCreatedEvent extends DaoEventBase {
  kind: 'proposal_created';
  proposer?: string;
  title?: string;
  votingStartsMs: number;
  votingEndsMs: number;
  /** Minimum total participation (for + against) for the proposal to pass. */
  quorum?: bigint | string | number;
  /** Total votable power, used to turn raw weights into shares. */
  totalVotingPower: bigint | string | number;
}

export interface ProposalQueuedEvent extends DaoEventBase {
  kind: 'proposal_queued';
  /** When the timelock releases the proposal for execution. */
  executableAtMs?: number;
}

export interface VoteCastEvent extends DaoEventBase {
  kind: 'vote_cast';
  voter: string;
  support: boolean;
  weight: bigint | string | number;
}

/**
 * Looks up a voter's voting power at a point in time. Supplied by the worker
 * (token balance history / checkpoints); injected so the sentinel stays pure.
 */
export type VotingPowerLookup = (
  contractId: string,
  voter: string,
  atMs: number,
) => Promise<bigint | null> | bigint | null;

export type DaoAlertType =
  | 'PROPOSAL_CREATED'
  | 'PROPOSAL_QUEUED'
  | 'FLASH_VOTE_RISK'
  | 'WHALE_VOTE'
  | 'OUTCOME_FLIP_LAST_MINUTE';

export interface DaoAlert {
  type: DaoAlertType;
  severity: 'INFO' | 'WARNING' | 'URGENT';
  contractId: string;
  proposalId: string;
  txHash: string;
  ledgerSeq: number;
  voter?: string;
  /** Voting power the voter gained inside the flash-vote window, as a share of total power (0-1). */
  acquiredPowerShare?: number;
  /** Seconds the voter held the power before voting, when known. */
  holdingDurationMs?: number;
  weightShare?: number;
  previousOutcome?: 'PASSING' | 'FAILING';
  newOutcome?: 'PASSING' | 'FAILING';
  summary: string;
  timestamp: string;
}

export type DaoAlertHandler = (alert: DaoAlert) => void | Promise<void>;

interface ProposalState {
  contractId: string;
  proposalId: string;
  votingStartsMs: number;
  votingEndsMs: number;
  quorum: bigint;
  totalVotingPower: bigint;
  votesFor: bigint;
  votesAgainst: bigint;
  voters: Set<string>;
  queued: boolean;
}

function toBigInt(value: bigint | string | number | undefined, fallback = 0n): bigint {
  if (value === undefined) return fallback;
  try {
    return BigInt(value);
  } catch {
    return fallback;
  }
}

function share(part: bigint, whole: bigint): number {
  if (whole <= 0n) return 0;
  // Scale before dividing so bigint precision survives the conversion to number.
  return Number((part * 1_000_000n) / whole) / 1_000_000;
}

function outcomeOf(state: ProposalState): 'PASSING' | 'FAILING' {
  const participation = state.votesFor + state.votesAgainst;
  return state.votesFor > state.votesAgainst && participation >= state.quorum ? 'PASSING' : 'FAILING';
}

export class DaoGovernanceSentinel {
  private readonly config: DaoSentinelConfig;
  private readonly proposals = new Map<string, ProposalState>();
  private readonly handlers = new Set<DaoAlertHandler>();
  private readonly votingPower: VotingPowerLookup | null;

  constructor(
    config: Partial<DaoSentinelConfig> = {},
    votingPower: VotingPowerLookup | null = null,
  ) {
    this.config = { ...DAO_SENTINEL_DEFAULTS, ...config };
    this.votingPower = votingPower;
  }

  public subscribe(handler: DaoAlertHandler): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  public clear(): void {
    this.proposals.clear();
    this.handlers.clear();
  }

  /** Processes one governance event, notifies subscribers and returns the alerts raised. */
  public async processEvent(event: DaoEvent): Promise<DaoAlert[]> {
    let alerts: DaoAlert[];
    switch (event.kind) {
      case 'proposal_created':
        alerts = this.onProposalCreated(event);
        break;
      case 'proposal_queued':
        alerts = this.onProposalQueued(event);
        break;
      case 'vote_cast':
        alerts = await this.onVoteCast(event);
        break;
      default:
        alerts = [];
    }

    for (const alert of alerts) await this.dispatch(alert);
    return alerts;
  }

  /** Current tally for a tracked proposal, or null when the proposal was never seen. */
  public getProposalTally(contractId: string, proposalId: string) {
    const state = this.proposals.get(this.key(contractId, proposalId));
    if (!state) return null;
    return {
      votesFor: state.votesFor,
      votesAgainst: state.votesAgainst,
      outcome: outcomeOf(state),
      voterCount: state.voters.size,
    };
  }

  private onProposalCreated(event: ProposalCreatedEvent): DaoAlert[] {
    this.proposals.set(this.key(event.contractId, event.proposalId), {
      contractId: event.contractId,
      proposalId: event.proposalId,
      votingStartsMs: event.votingStartsMs,
      votingEndsMs: event.votingEndsMs,
      quorum: toBigInt(event.quorum),
      totalVotingPower: toBigInt(event.totalVotingPower),
      votesFor: 0n,
      votesAgainst: 0n,
      voters: new Set(),
      queued: false,
    });

    return [
      this.alert(event, 'PROPOSAL_CREATED', 'INFO',
        `New governance proposal ${event.proposalId}${event.title ? ` "${event.title}"` : ''} ` +
          `submitted on ${event.contractId}${event.proposer ? ` by ${event.proposer}` : ''}.`),
    ];
  }

  private onProposalQueued(event: ProposalQueuedEvent): DaoAlert[] {
    const state = this.proposals.get(this.key(event.contractId, event.proposalId));
    if (state) {
      if (state.queued) return [];
      state.queued = true;
    }

    const eta = event.executableAtMs ? ` Executable from ${new Date(event.executableAtMs).toISOString()}.` : '';
    return [
      this.alert(event, 'PROPOSAL_QUEUED', 'WARNING',
        `Governance proposal ${event.proposalId} on ${event.contractId} was queued for execution.${eta}`),
    ];
  }

  private async onVoteCast(event: VoteCastEvent): Promise<DaoAlert[]> {
    const state = this.proposals.get(this.key(event.contractId, event.proposalId));
    if (!state) {
      logger.debug({ proposalId: event.proposalId }, 'Vote for untracked proposal ignored');
      return [];
    }

    const weight = toBigInt(event.weight);
    const alerts: DaoAlert[] = [];
    const before = outcomeOf(state);

    if (event.support) state.votesFor += weight;
    else state.votesAgainst += weight;
    state.voters.add(event.voter);
    const after = outcomeOf(state);

    const weightShare = share(weight, state.totalVotingPower);
    if (weightShare >= this.config.whaleVoteShare) {
      alerts.push({
        ...this.alert(event, 'WHALE_VOTE', 'WARNING',
          `${event.voter} cast a ${(weightShare * 100).toFixed(1)}% voting-power vote ` +
            `${event.support ? 'for' : 'against'} proposal ${event.proposalId}.`),
        voter: event.voter,
        weightShare,
      });
    }

    const flash = await this.checkFlashVote(event, state);
    if (flash) alerts.push(flash);

    if (before !== after && this.inFinalPeriod(state, event.timestampMs)) {
      alerts.push({
        ...this.alert(event, 'OUTCOME_FLIP_LAST_MINUTE', 'URGENT',
          `Proposal ${event.proposalId} flipped from ${before} to ${after} in the final ` +
            `${Math.round(this.config.finalPeriodShare * 100)}% of voting, after a vote by ${event.voter}.`),
        voter: event.voter,
        weightShare,
        previousOutcome: before,
        newOutcome: after,
      });
    }

    return alerts;
  }

  /** Flags voters who gained more than the configured share of total power within the window before voting. */
  private async checkFlashVote(event: VoteCastEvent, state: ProposalState): Promise<DaoAlert | null> {
    if (!this.votingPower || state.totalVotingPower <= 0n) return null;

    const windowStart = event.timestampMs - this.config.flashVoteWindowMs;
    let current: bigint | null;
    let earlier: bigint | null;
    try {
      current = await this.votingPower(event.contractId, event.voter, event.timestampMs);
      earlier = await this.votingPower(event.contractId, event.voter, windowStart);
    } catch (err) {
      logger.warn(
        { voter: event.voter, err: err instanceof Error ? err.message : String(err) },
        'Voting power lookup failed; flash-vote check skipped',
      );
      return null;
    }
    if (current === null) return null;

    const acquired = current - (earlier ?? 0n);
    const acquiredShare = share(acquired, state.totalVotingPower);
    if (acquiredShare <= this.config.flashVotePowerShare) return null;

    return {
      ...this.alert(event, 'FLASH_VOTE_RISK', 'URGENT',
        `${event.voter} acquired ${(acquiredShare * 100).toFixed(1)}% of total voting power within ` +
          `${Math.round(this.config.flashVoteWindowMs / HOUR_MS)}h of voting on proposal ${event.proposalId}.`),
      voter: event.voter,
      acquiredPowerShare: acquiredShare,
      holdingDurationMs: earlier === null || earlier === 0n ? undefined : this.config.flashVoteWindowMs,
      weightShare: share(toBigInt(event.weight), state.totalVotingPower),
    };
  }

  private inFinalPeriod(state: ProposalState, atMs: number): boolean {
    const duration = state.votingEndsMs - state.votingStartsMs;
    if (duration <= 0 || atMs > state.votingEndsMs) return false;
    return atMs >= state.votingEndsMs - duration * this.config.finalPeriodShare;
  }

  private alert(
    event: DaoEvent,
    type: DaoAlertType,
    severity: DaoAlert['severity'],
    summary: string,
  ): DaoAlert {
    return {
      type,
      severity,
      contractId: event.contractId,
      proposalId: event.proposalId,
      txHash: event.txHash,
      ledgerSeq: event.ledgerSeq,
      summary,
      timestamp: new Date(event.timestampMs).toISOString(),
    };
  }

  private async dispatch(alert: DaoAlert): Promise<void> {
    for (const handler of this.handlers) {
      try {
        await handler(alert);
      } catch (err) {
        logger.warn(
          { proposalId: alert.proposalId, err: err instanceof Error ? err.message : String(err) },
          'DAO alert handler failed',
        );
      }
    }
  }

  private key(contractId: string, proposalId: string): string {
    return `${contractId}:${proposalId}`;
  }
}

export const daoGovernanceSentinel = new DaoGovernanceSentinel();
