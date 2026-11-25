import chalk from 'chalk';
import type { PaymentDTO, SorobanEventDTO } from '../lib/types.js';

export type TailEventKind = 'payment' | 'soroban';

export interface TailPaymentEvent {
  kind: 'payment';
  id: string;
  walletId?: string;
  walletAddress?: string;
  txHash?: string;
  fromAddress?: string;
  toAddress?: string;
  amount: number | string;
  asset: string;
  contractId?: string;
  memo?: string | null;
  receivedAt?: Date | string;
}

export interface TailSorobanEvent {
  kind: 'soroban';
  id: string;
  contractId?: string;
  topic?: string[];
  asset?: string;
  from?: string;
  to?: string;
  amount?: number | string;
  txHash?: string;
  ledger?: number;
  receivedAt?: Date | string;
}

export type TailEvent = TailPaymentEvent | TailSorobanEvent;

export interface TailFilter {
  wallet?: string;
  contract?: string;
  asset?: string;
  minAmount?: number;
}

export interface TailSessionStats {
  startedAt: number;
  endedAt: number;
  inspected: number;
  matched: number;
}

/** Converts a payment stream record into the canonical tail event shape. */
export function paymentToTailEvent(payment: PaymentDTO): TailPaymentEvent {
  return {
    kind: 'payment',
    id: payment.id,
    walletId: payment.walletId,
    txHash: payment.txHash,
    fromAddress: payment.fromAddress,
    amount: payment.amount,
    asset: payment.asset,
    memo: payment.memo,
    receivedAt: payment.receivedAt,
  };
}

/** Converts a Soroban event stream record into the canonical tail event shape. */
export function sorobanEventToTailEvent(event: SorobanEventDTO): TailSorobanEvent {
  return {
    kind: 'soroban',
    id: event.id,
    contractId: event.contractId,
    topic: event.topic,
    asset: event.asset,
    from: event.from,
    to: event.to,
    amount: event.amount,
    txHash: event.txHash,
    ledger: event.ledger,
    receivedAt: event.createdAt,
  };
}

function parseAmount(value: number | string | undefined): number | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function includesInsensitive(value: string | undefined, needle: string): boolean {
  return typeof value === 'string' && value.toLowerCase().includes(needle.toLowerCase());
}

function equalsInsensitive(value: string | undefined, needle: string): boolean {
  return typeof value === 'string' && value.trim().toUpperCase() === needle.trim().toUpperCase();
}

function addressesOf(event: TailEvent): Array<string | undefined> {
  if (event.kind === 'payment') {
    return [event.walletAddress, event.walletId, event.fromAddress, event.toAddress];
  }
  return [event.from, event.to, event.contractId];
}

/**
 * Applies every supplied filter to one event. Filters are ANDed together;
 * addresses and contract ids are matched case-insensitively as substrings so
 * truncated addresses still work, while asset codes use an exact match.
 */
export function matchesTailFilter(event: TailEvent, filter: TailFilter): boolean {
  const { wallet, contract, asset } = filter;

  if (wallet && !addressesOf(event).some((address) => includesInsensitive(address, wallet))) {
    return false;
  }

  if (contract && !includesInsensitive(event.contractId, contract)) return false;

  if (asset && !equalsInsensitive(event.asset, asset)) return false;

  if (filter.minAmount !== undefined && Number.isFinite(filter.minAmount)) {
    const amount = parseAmount(event.amount);
    if (amount === undefined || amount < filter.minAmount) return false;
  }

  return true;
}

function timestampOf(event: TailEvent): string | undefined {
  if (!event.receivedAt) return undefined;
  const date = event.receivedAt instanceof Date ? event.receivedAt : new Date(event.receivedAt);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

/**
 * Serializes one event into a single NDJSON line. JSON.stringify escapes any
 * embedded newlines in string values, so the result is always pipe-safe.
 */
export function serializeNdjson(event: TailEvent): string {
  const record: Record<string, unknown> = { type: event.kind, id: event.id };
  const amount = parseAmount(event.amount);

  const fields: Array<[string, unknown]> = event.kind === 'payment'
    ? [
        ['walletId', event.walletId],
        ['walletAddress', event.walletAddress],
        ['from', event.fromAddress],
        ['to', event.toAddress],
        ['txHash', event.txHash],
        ['asset', event.asset],
        ['amount', amount ?? event.amount],
        ['memo', event.memo],
        ['contractId', event.contractId],
      ]
    : [
        ['contractId', event.contractId],
        ['asset', event.asset],
        ['from', event.from],
        ['to', event.to],
        ['amount', amount ?? event.amount],
        ['topic', event.topic],
        ['txHash', event.txHash],
        ['ledger', event.ledger],
      ];

  for (const [key, value] of fields) {
    if (value !== undefined && value !== null && value !== '') record[key] = value;
  }

  const timestamp = timestampOf(event);
  if (timestamp) record.timestamp = timestamp;

  return JSON.stringify(record);
}

function highlight(value: string, active: boolean): string {
  return active ? chalk.bgYellow.black(value) : chalk.cyan(value);
}

/** Renders one event for human-readable terminal output, highlighting matched filter values. */
export function formatHumanEvent(event: TailEvent, filter: TailFilter = {}): string {
  const time = timestampOf(event)?.slice(11, 19) ?? '--:--:--';
  const kind = event.kind === 'payment' ? 'PAYMENT' : 'SOROBAN';
  const amount = String(amountForDisplay(event));
  const asset = event.asset ?? '—';
  const address = event.kind === 'payment'
    ? (event.fromAddress ?? event.walletAddress ?? event.walletId ?? '')
    : (event.from ?? event.contractId ?? '');
  const detail = event.kind === 'payment' ? (event.memo ?? '') : (event.topic ?? []).join(',');

  const walletHit = Boolean(filter.wallet && addressesOf(event).some((value) => includesInsensitive(value, filter.wallet ?? '')));
  const contractHit = Boolean(filter.contract && includesInsensitive(event.contractId, filter.contract));
  const assetHit = Boolean(filter.asset && equalsInsensitive(event.asset, filter.asset));

  const coloredKind = event.kind === 'payment' ? chalk.green(kind) : chalk.magenta(kind);
  return [
    chalk.gray(time),
    '│',
    coloredKind.padEnd(15),
    '│',
    highlight(amount, filter.minAmount !== undefined).padStart(12),
    highlight(asset.padEnd(7), assetHit),
    '│',
    highlight(address.slice(0, 20), walletHit || contractHit),
    detail ? chalk.gray(` ${detail.slice(0, 30)}`) : '',
  ].join(' ').trimEnd();
}

function amountForDisplay(event: TailEvent): string | number {
  return parseAmount(event.amount) ?? event.amount ?? '—';
}

/** Formats the SIGINT session summary. Duration and rates are deterministic to ease testing. */
export function formatSessionSummary(stats: TailSessionStats): string {
  const durationMs = Math.max(0, stats.endedAt - stats.startedAt);
  const seconds = durationMs / 1000;
  const rate = seconds > 0 ? stats.matched / seconds : 0;

  return [
    '',
    chalk.gray('─'.repeat(64)),
    chalk.bold('⏹  Tail session summary'),
    `  Duration:         ${seconds.toFixed(1)}s`,
    `  Events inspected: ${stats.inspected}`,
    `  Matched:          ${stats.matched}`,
    `  Match rate:       ${rate.toFixed(2)}/sec`,
    chalk.gray('─'.repeat(64)),
  ].join('\n');
}
