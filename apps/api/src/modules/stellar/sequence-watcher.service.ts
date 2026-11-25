import * as StellarSdk from 'stellar-sdk';
import { prisma } from '../../lib/prisma';
import { stellar } from '../../lib/stellar';
import { redisCache } from '../../lib/redis';
import { createLogger } from '../../lib/logger';
import { deliverUserAlert, escapeTelegramHtml } from './alert-delivery';

const log = createLogger({ module: 'SequencePreconditionWatcher' });

export interface DecodedPreconditions {
  version: 'none' | 'time' | 'v2';
  timeBounds: { minTime: string; maxTime: string } | null;
  /** A maxLedger of 0 means there is no upper bound. */
  ledgerBounds: { minLedger: number; maxLedger: number } | null;
  minSeqNum: string | null;
  /** Seconds. */
  minSeqAge: string | null;
  minSeqLedgerGap: number | null;
  extraSigners: string[];
}

export interface DecodedEnvelope {
  sourceAccount: string;
  sequence: string;
  preconditions: DecodedPreconditions;
}

export interface SequenceDelta {
  previousSeq: string | null;
  bumpTo: string;
  /** bumpTo - previousSeq; null when the prior sequence is unknown. */
  delta: string | null;
  /** False when the operation left the sequence unchanged (bumpTo <= previousSeq). */
  effective: boolean;
  /** The account sequence after the operation. */
  watermark: string;
}

export interface PendingProposal {
  id: string;
  innerTxHash: string;
  envelopeXdr: string;
}

export interface InvalidatedProposal {
  id: string;
  innerTxHash: string;
  sequence: string;
  preconditions: DecodedPreconditions;
}

export type SequenceAlertType = 'BUMP_SEQUENCE' | 'MIN_SEQ_NUM_JUMP';
export type SequenceAlertSeverity = 'CRITICAL' | 'WARNING';

export interface SequenceAlert {
  eventType: SequenceAlertType;
  severity: SequenceAlertSeverity;
  account: string;
  previousSeq: string | null;
  newSeq: string;
  delta: string | null;
  operationId: string;
  transactionHash?: string;
  preconditions: DecodedPreconditions | null;
  invalidatedProposals: InvalidatedProposal[];
  occurredAt: string;
  message: string;
}

/** The subset of a Horizon transaction the watcher reads. */
export interface SequenceTransaction {
  hash?: string;
  source_account?: string;
  source_account_sequence?: string;
  envelope_xdr?: string;
  inner_transaction?: { hash?: string };
}

/** A Horizon operation record joined with its transaction. */
export interface SequenceOperation {
  id?: string;
  paging_token?: string;
  type: string;
  created_at?: string;
  transaction_hash?: string;
  transaction_successful?: boolean;
  source_account?: string;
  bump_to?: string;
  transaction_attr?: SequenceTransaction;
}

// ── XDR decoding ────────────────────────────────────────────────────────────

const NO_PRECONDITIONS: DecodedPreconditions = {
  version: 'none',
  timeBounds: null,
  ledgerBounds: null,
  minSeqNum: null,
  minSeqAge: null,
  minSeqLedgerGap: null,
  extraSigners: [],
};

function decodeTimeBounds(bounds: StellarSdk.xdr.TimeBounds | null | undefined) {
  if (!bounds) return null;
  return { minTime: bounds.minTime().toString(), maxTime: bounds.maxTime().toString() };
}

function decodeConditions(cond: StellarSdk.xdr.Preconditions): DecodedPreconditions {
  switch (cond.switch().name) {
    case 'precondTime':
      return { ...NO_PRECONDITIONS, version: 'time', timeBounds: decodeTimeBounds(cond.timeBounds()) };
    case 'precondV2': {
      const v2 = cond.v2();
      const ledgerBounds = v2.ledgerBounds();
      const minSeqNum = v2.minSeqNum();
      const minSeqAge = v2.minSeqAge().toString();
      const minSeqLedgerGap = v2.minSeqLedgerGap();
      return {
        version: 'v2',
        timeBounds: decodeTimeBounds(v2.timeBounds()),
        ledgerBounds: ledgerBounds
          ? { minLedger: ledgerBounds.minLedger(), maxLedger: ledgerBounds.maxLedger() }
          : null,
        minSeqNum: minSeqNum ? minSeqNum.toString() : null,
        // Zero is the protocol's "constraint not set" value for both fields.
        minSeqAge: minSeqAge === '0' ? null : minSeqAge,
        minSeqLedgerGap: minSeqLedgerGap === 0 ? null : minSeqLedgerGap,
        extraSigners: v2.extraSigners().map((signer) => StellarSdk.SignerKey.encodeSignerKey(signer)),
      };
    }
    default:
      return { ...NO_PRECONDITIONS };
  }
}

function muxedToAddress(account: StellarSdk.xdr.MuxedAccount): string {
  const raw = account.switch().name === 'keyTypeMuxedEd25519' ? account.med25519().ed25519() : account.ed25519();
  return StellarSdk.StrKey.encodeEd25519PublicKey(raw);
}

/**
 * Decodes the source, sequence and CAP-0021 preconditions of a transaction
 * envelope. For a fee-bump, these come from the inner transaction, which is
 * the one that consumes the sequence number.
 */
export function decodeEnvelope(envelopeXdr: string): DecodedEnvelope {
  const envelope = StellarSdk.xdr.TransactionEnvelope.fromXDR(envelopeXdr, 'base64');

  switch (envelope.switch().name) {
    case 'envelopeTypeTxV0': {
      const tx = envelope.v0().tx();
      const timeBounds = decodeTimeBounds(tx.timeBounds());
      return {
        sourceAccount: StellarSdk.StrKey.encodeEd25519PublicKey(tx.sourceAccountEd25519()),
        sequence: tx.seqNum().toString(),
        preconditions: timeBounds ? { ...NO_PRECONDITIONS, version: 'time', timeBounds } : { ...NO_PRECONDITIONS },
      };
    }
    case 'envelopeTypeTx': {
      const tx = envelope.v1().tx();
      return {
        sourceAccount: muxedToAddress(tx.sourceAccount()),
        sequence: tx.seqNum().toString(),
        preconditions: decodeConditions(tx.cond()),
      };
    }
    case 'envelopeTypeTxFeeBump': {
      const tx = envelope.feeBump().tx().innerTx().v1().tx();
      return {
        sourceAccount: muxedToAddress(tx.sourceAccount()),
        sequence: tx.seqNum().toString(),
        preconditions: decodeConditions(tx.cond()),
      };
    }
    default:
      throw new Error(`Unsupported envelope type: ${envelope.switch().name}`);
  }
}

// ── Pure sequence logic ─────────────────────────────────────────────────────

export function calculateSequenceDelta(previousSeq: string | null, bumpTo: string): SequenceDelta {
  const target = BigInt(bumpTo);
  if (previousSeq === null) {
    return { previousSeq: null, bumpTo, delta: null, effective: true, watermark: bumpTo };
  }
  const previous = BigInt(previousSeq);
  const effective = target > previous;
  return {
    previousSeq,
    bumpTo,
    delta: (target - previous).toString(),
    effective,
    watermark: effective ? bumpTo : previousSeq,
  };
}

/**
 * Finds stored proposals the new account sequence has made unsubmittable. A
 * transaction is only valid while its sequence is above the account's, even
 * with minSeqNum, so anything at or below the water-mark can never apply.
 * Undecodable envelopes are skipped rather than reported as invalidated.
 */
export function findInvalidatedProposals(
  account: string,
  watermark: string,
  proposals: PendingProposal[],
  onDecodeError?: (proposal: PendingProposal, err: unknown) => void,
): InvalidatedProposal[] {
  const limit = BigInt(watermark);
  const invalidated: InvalidatedProposal[] = [];

  for (const proposal of proposals) {
    try {
      const decoded = decodeEnvelope(proposal.envelopeXdr);
      if (decoded.sourceAccount === account && BigInt(decoded.sequence) <= limit) {
        invalidated.push({
          id: proposal.id,
          innerTxHash: proposal.innerTxHash,
          sequence: decoded.sequence,
          preconditions: decoded.preconditions,
        });
      }
    } catch (err: unknown) {
      onDecodeError?.(proposal, err);
    }
  }
  return invalidated;
}

export interface SequenceEvent {
  eventType: SequenceAlertType;
  account: string;
  sequence: SequenceDelta;
  preconditions: DecodedPreconditions | null;
  /** Hash of the transaction that moved the sequence; it cannot invalidate itself. */
  consumedHash?: string;
}

/**
 * Extracts a sequence jump from an operation. Besides bump_sequence, a
 * transaction with minSeqNum set can leapfrog the account's sequence too.
 */
export function detectSequenceEvent(op: SequenceOperation, watchedAccount: string): SequenceEvent | null {
  if (op.transaction_successful === false) return null;

  const tx = op.transaction_attr;
  let decoded: DecodedEnvelope | null = null;
  if (tx?.envelope_xdr) {
    try {
      decoded = decodeEnvelope(tx.envelope_xdr);
    } catch (err: unknown) {
      log.warn(`Could not decode envelope for ${op.id ?? 'operation'}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  const txSource = decoded?.sourceAccount ?? tx?.source_account;
  const txSequence = decoded?.sequence ?? tx?.source_account_sequence ?? null;
  const consumedHash = tx?.inner_transaction?.hash ?? tx?.hash ?? op.transaction_hash;

  if (op.type === 'bump_sequence' && op.bump_to && op.source_account === watchedAccount) {
    // The transaction consumes its own sequence before its operations run, so
    // it is the exact prior value only when the bumping account is its source.
    const previous = txSource === watchedAccount ? txSequence : null;
    const sequence = calculateSequenceDelta(previous, op.bump_to);
    if (!sequence.effective) return null;
    return {
      eventType: 'BUMP_SEQUENCE',
      account: watchedAccount,
      sequence,
      preconditions: decoded?.preconditions ?? null,
      consumedHash,
    };
  }

  const minSeqNum = decoded?.preconditions.minSeqNum;
  if (decoded && minSeqNum && decoded.sourceAccount === watchedAccount) {
    const sequence = calculateSequenceDelta(minSeqNum, decoded.sequence);
    // minSeqNum === sequence - 1 is an ordinary, non-skipping transaction.
    if (sequence.delta === null || BigInt(sequence.delta) <= 1n) return null;
    return {
      eventType: 'MIN_SEQ_NUM_JUMP',
      account: watchedAccount,
      sequence,
      preconditions: decoded.preconditions,
      consumedHash,
    };
  }
  return null;
}

export function buildSequenceAlert(
  event: SequenceEvent,
  op: SequenceOperation,
  invalidatedProposals: InvalidatedProposal[],
): SequenceAlert {
  const count = invalidatedProposals.length;
  const jump = event.sequence.delta === null ? 'an unknown amount' : `${event.sequence.delta}`;
  const label = event.eventType === 'BUMP_SEQUENCE' ? 'bump_sequence' : 'minSeqNum transaction';
  return {
    eventType: event.eventType,
    severity: count > 0 ? 'CRITICAL' : 'WARNING',
    account: event.account,
    previousSeq: event.sequence.previousSeq,
    newSeq: event.sequence.watermark,
    delta: event.sequence.delta,
    operationId: op.id ?? op.paging_token ?? '',
    transactionHash: op.transaction_hash,
    preconditions: event.preconditions,
    invalidatedProposals,
    occurredAt: op.created_at ?? new Date().toISOString(),
    message:
      `${label} moved ${event.account.slice(0, 8)}... to sequence ${event.sequence.watermark} (jump: ${jump}); ` +
      `${count} pending multi-sig proposal(s) invalidated.`,
  };
}

export function buildSequenceWebhookPayload(alert: SequenceAlert): Record<string, unknown> {
  return {
    event: 'account.sequence_jump',
    timestamp: alert.occurredAt,
    data: { ...alert },
  };
}

export function buildSequenceTelegramMessage(alert: SequenceAlert): string {
  const hashes = alert.invalidatedProposals
    .slice(0, 10)
    .map((proposal) => `<code>${escapeTelegramHtml(proposal.innerTxHash)}</code>`);
  const remaining = alert.invalidatedProposals.length - hashes.length;
  return [
    `<b>${alert.severity}: Sequence number jump</b>`,
    `<b>Account:</b> <code>${escapeTelegramHtml(alert.account)}</code>`,
    escapeTelegramHtml(alert.message),
    hashes.length > 0 ? `<b>Invalidated:</b>\n${hashes.join('\n')}` : '',
    remaining > 0 ? `...and ${remaining} more` : '',
    alert.transactionHash ? `<b>Transaction:</b> <code>${escapeTelegramHtml(alert.transactionHash)}</code>` : '',
  ]
    .filter(Boolean)
    .join('\n');
}

// ── Service ─────────────────────────────────────────────────────────────────

const CURSOR_KEY_PREFIX = 'sequence-watcher:cursor:';
const ALERT_KEY_PREFIX = 'sequence-watcher:alert:';
const ALERT_DEDUPE_TTL_SECONDS = 30 * 24 * 60 * 60;
const OPERATIONS_PAGE_SIZE = 100;

export interface SequenceWatcherDeps {
  /** Pending proposals and the users to notify for an account. */
  loadTreasury(account: string): Promise<{ proposals: PendingProposal[]; signerUserIds: string[] } | null>;
  /** Users owning the account as a monitored wallet. */
  loadWalletUserIds(account: string): Promise<string[]>;
  /** Whether a transaction hash is already on the ledger. Must throw if unknown. */
  isOnLedger(hash: string): Promise<boolean>;
  markExpired(proposalIds: string[]): Promise<void>;
  notify(userIds: string[], alert: SequenceAlert): Promise<void>;
}

export const defaultSequenceWatcherDeps: SequenceWatcherDeps = {
  async loadTreasury(account) {
    const treasury = await prisma.multisigTreasury.findUnique({
      where: { publicKey: account },
      include: {
        signerWatchers: { select: { userId: true } },
        pendingTxs: {
          where: { status: { in: ['pending', 'threshold_met'] } },
          select: { id: true, innerTxHash: true, envelopeXdr: true },
        },
      },
    });
    if (!treasury) return null;
    return {
      proposals: treasury.pendingTxs,
      signerUserIds: treasury.signerWatchers.map((watcher) => watcher.userId),
    };
  },
  async loadWalletUserIds(account) {
    const wallets = await prisma.wallet.findMany({
      where: { publicKey: account, deletedAt: null },
      select: { userId: true },
    });
    return wallets.map((wallet) => wallet.userId);
  },
  isOnLedger: (hash) => stellar.isTransactionOnLedger(hash),
  async markExpired(proposalIds) {
    await prisma.pendingMultisigTransaction.updateMany({
      where: { id: { in: proposalIds }, status: { in: ['pending', 'threshold_met'] } },
      data: { status: 'expired' },
    });
  },
  async notify(userIds, alert) {
    const payload = buildSequenceWebhookPayload(alert);
    const text = buildSequenceTelegramMessage(alert);
    for (const userId of userIds) {
      await deliverUserAlert(userId, payload, text);
    }
  },
};

export class SequencePreconditionWatcher {
  constructor(private readonly deps: SequenceWatcherDeps = defaultSequenceWatcherDeps) {}

  /** Handles one operation and returns the alert raised, if any. */
  async processOperation(op: SequenceOperation, account: string): Promise<SequenceAlert | null> {
    const event = detectSequenceEvent(op, account);
    if (!event) return null;

    const dedupeKey = `${ALERT_KEY_PREFIX}${event.consumedHash ?? op.id}:${account}:${event.sequence.watermark}`;
    if (!(await redisCache.setNx(dedupeKey, '1', ALERT_DEDUPE_TTL_SECONDS))) return null;

    try {
      const treasury = await this.deps.loadTreasury(account);
      const candidates = findInvalidatedProposals(
        account,
        event.sequence.watermark,
        treasury?.proposals ?? [],
        (proposal, err) => {
          log.warn(`Could not decode proposal ${proposal.id}: ${err instanceof Error ? err.message : String(err)}`);
        },
      );

      // A proposal at or below the water-mark may simply have executed, in
      // which case it was not cancelled.
      const invalidated: InvalidatedProposal[] = [];
      for (const candidate of candidates) {
        if (candidate.innerTxHash === event.consumedHash) continue;
        if (!(await this.deps.isOnLedger(candidate.innerTxHash))) invalidated.push(candidate);
      }

      const alert = buildSequenceAlert(event, op, invalidated);
      const walletUsers = await this.deps.loadWalletUserIds(account);
      const recipients = Array.from(new Set([...walletUsers, ...(treasury?.signerUserIds ?? [])]));

      log.warn(`[${alert.severity}] ${alert.message}`);
      await this.deps.notify(recipients, alert);
      if (invalidated.length > 0) {
        await this.deps.markExpired(invalidated.map((proposal) => proposal.id));
      }
      return alert;
    } catch (err: unknown) {
      // Release the claim so the retried pass can raise this alert.
      await redisCache.del(dedupeKey);
      throw err;
    }
  }

  private async scanAccount(account: string): Promise<number> {
    const cursorKey = `${CURSOR_KEY_PREFIX}${account}`;
    const cursor = await redisCache.get(cursorKey);

    if (!cursor) {
      // First sight: start from "now" so history is not replayed as fresh alerts.
      const latest = await stellar.getLatestOperationPagingToken(account);
      if (latest.ok) await redisCache.set(cursorKey, latest.token ?? '0');
      return 0;
    }

    const result = await stellar.getAccountOperationsSince(account, cursor, OPERATIONS_PAGE_SIZE, {
      includeTransactions: true,
    });
    if (!result.ok) return 0;

    let emitted = 0;
    for (const record of result.records as SequenceOperation[]) {
      if (await this.processOperation(record, account)) emitted += 1;
      if (record.paging_token) await redisCache.set(cursorKey, record.paging_token);
    }
    return emitted;
  }

  /** One pass over the monitored accounts; each account's failure is isolated. */
  async runPass(publicKeys: string[]): Promise<number> {
    let emitted = 0;
    for (const account of new Set(publicKeys)) {
      try {
        emitted += await this.scanAccount(account);
      } catch (err: unknown) {
        log.warn(`Sequence scan failed for ${account.slice(0, 8)}...: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    return emitted;
  }
}

export const sequencePreconditionWatcher = new SequencePreconditionWatcher();
