import { prisma } from '../../lib/prisma';
import { stellar } from '../../lib/stellar';
import { redisCache } from '../../lib/redis';
import { createLogger } from '../../lib/logger';
import { deliverUserAlert, escapeTelegramHtml } from './alert-delivery';

const log = createLogger({ module: 'ManageDataSentinel' });

export type ManageDataChange = 'CREATED' | 'UPDATED' | 'DELETED';
export type ManageDataSeverity = 'CRITICAL' | 'WARNING' | 'INFO';

/** A Horizon `manage_data` operation record. */
export interface ManageDataOperation {
  id?: string;
  paging_token?: string;
  type: string;
  created_at?: string;
  transaction_hash?: string;
  transaction_successful?: boolean;
  source_account?: string;
  name?: string;
  /** Base64 value; null or absent means the entry was deleted. */
  value?: string | null;
}

export interface DecodedDataValue {
  base64: string;
  hex: string;
  /** Set only when the bytes are valid, fully printable UTF-8. */
  utf8: string | null;
}

export interface ManageDataAlert {
  eventType: 'ACCOUNT_DATA_CHANGED';
  change: ManageDataChange;
  severity: ManageDataSeverity;
  protectedKey: boolean;
  account: string;
  key: string;
  before: DecodedDataValue | null;
  after: DecodedDataValue | null;
  operationId: string;
  transactionHash?: string;
  occurredAt: string;
  message: string;
}

export type AccountDataState = Map<string, string>;

/**
 * Decodes an entry value for display. Format and bidirectional control
 * characters count as unprintable, so a value cannot visually spoof an alert.
 */
export function decodeDataValue(base64: string): DecodedDataValue {
  const bytes = Buffer.from(base64, 'base64');
  let utf8: string | null = null;
  try {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    if (text.length > 0 && !/\p{C}/u.test(text)) utf8 = text;
  } catch {
    utf8 = null;
  }
  return { base64, hex: bytes.toString('hex'), utf8 };
}

/** Matches `config.memo_required` exactly and anything under `auth.` or `did.`. */
export function isProtectedDataKey(key: string): boolean {
  return key === 'config.memo_required' || key.startsWith('auth.') || key.startsWith('did.');
}

function severityFor(change: ManageDataChange, protectedKey: boolean): ManageDataSeverity {
  if (protectedKey) return change === 'CREATED' ? 'WARNING' : 'CRITICAL';
  return change === 'CREATED' ? 'INFO' : 'WARNING';
}

function short(address: string): string {
  return `${address.slice(0, 8)}...`;
}

function display(value: DecodedDataValue | null): string {
  if (!value) return '(none)';
  return value.utf8 !== null ? JSON.stringify(value.utf8) : `0x${value.hex}`;
}

function normalizeValue(value: string | null | undefined): string | null {
  return value === undefined || value === null || value === '' ? null : value;
}

/**
 * Compares an operation with the entry's prior value. Returns null when nothing
 * changed, which also makes replaying an already-applied operation harmless.
 */
export function diffManageData(
  op: ManageDataOperation,
  state: AccountDataState,
): ManageDataAlert | null {
  if (op.type !== 'manage_data' || op.transaction_successful === false) return null;
  if (!op.source_account || op.name === undefined) return null;

  const previous = state.get(op.name) ?? null;
  const next = normalizeValue(op.value);
  if (previous === next) return null;

  const change: ManageDataChange = next === null ? 'DELETED' : previous === null ? 'CREATED' : 'UPDATED';
  const protectedKey = isProtectedDataKey(op.name);
  const severity = severityFor(change, protectedKey);
  const before = previous === null ? null : decodeDataValue(previous);
  const after = next === null ? null : decodeDataValue(next);

  return {
    eventType: 'ACCOUNT_DATA_CHANGED',
    change,
    severity,
    protectedKey,
    account: op.source_account,
    key: op.name,
    before,
    after,
    operationId: op.id ?? op.paging_token ?? '',
    transactionHash: op.transaction_hash,
    occurredAt: op.created_at ?? new Date().toISOString(),
    message:
      `${protectedKey ? 'Protected data entry' : 'Data entry'} ${JSON.stringify(op.name)} ` +
      `${change.toLowerCase()} on ${short(op.source_account)}: ${display(before)} -> ${display(after)}.`,
  };
}

/** Applies an operation to the tracked state. */
export function applyManageData(op: ManageDataOperation, state: AccountDataState): void {
  if (op.type !== 'manage_data' || op.transaction_successful === false || op.name === undefined) return;
  const next = normalizeValue(op.value);
  if (next === null) state.delete(op.name);
  else state.set(op.name, next);
}

export function buildManageDataWebhookPayload(alert: ManageDataAlert): Record<string, unknown> {
  return {
    event: 'account.data_changed',
    timestamp: alert.occurredAt,
    data: {
      change: alert.change,
      severity: alert.severity,
      protectedKey: alert.protectedKey,
      account: alert.account,
      key: alert.key,
      before: alert.before,
      after: alert.after,
      operationId: alert.operationId,
      transactionHash: alert.transactionHash,
      message: alert.message,
    },
  };
}

export function buildManageDataTelegramMessage(alert: ManageDataAlert): string {
  return [
    `<b>${alert.severity}: Account data ${alert.change.toLowerCase()}</b>`,
    `<b>Account:</b> <code>${escapeTelegramHtml(alert.account)}</code>`,
    `<b>Key:</b> <code>${escapeTelegramHtml(alert.key)}</code>`,
    `<b>Before:</b> <code>${escapeTelegramHtml(display(alert.before))}</code>`,
    `<b>After:</b> <code>${escapeTelegramHtml(display(alert.after))}</code>`,
    alert.transactionHash ? `<b>Transaction:</b> <code>${escapeTelegramHtml(alert.transactionHash)}</code>` : '',
  ]
    .filter(Boolean)
    .join('\n');
}

export type ManageDataNotifier = (alert: ManageDataAlert) => Promise<void>;

export const deliverManageDataAlert: ManageDataNotifier = async (alert) => {
  const wallets = await prisma.wallet.findMany({
    where: { publicKey: alert.account, deletedAt: null },
    select: { userId: true },
  });
  const payload = buildManageDataWebhookPayload(alert);
  const text = buildManageDataTelegramMessage(alert);
  for (const userId of new Set(wallets.map((wallet) => wallet.userId))) {
    await deliverUserAlert(userId, payload, text);
  }
};

// ── Polling pass (called from the watcher worker) ───────────────────────────

const CURSOR_KEY_PREFIX = 'manage-data-sentinel:cursor:';
const STATE_KEY_PREFIX = 'manage-data-sentinel:state:';
const ALERT_KEY_PREFIX = 'manage-data-sentinel:alert:';
const ALERT_DEDUPE_TTL_SECONDS = 30 * 24 * 60 * 60;
const OPERATIONS_PAGE_SIZE = 100;

// Stored as entries: data entry names are attacker-controlled and may be `__proto__`.
function serializeState(state: AccountDataState): string {
  return JSON.stringify(Array.from(state.entries()));
}

function parseState(raw: string): AccountDataState {
  return new Map(JSON.parse(raw) as Array<[string, string]>);
}

async function seedAccount(publicKey: string): Promise<void> {
  // Read the cursor first: an operation landing between the two reads is then
  // replayed against state that already has it, and diffs to "no change".
  const latest = await stellar.getLatestOperationPagingToken(publicKey);
  if (!latest.ok) return;
  const data = await stellar.getAccountDataEntries(publicKey);
  if (!data) return;

  await redisCache.set(`${STATE_KEY_PREFIX}${publicKey}`, serializeState(new Map(Object.entries(data))));
  await redisCache.set(`${CURSOR_KEY_PREFIX}${publicKey}`, latest.token ?? '0');
}

async function scanAccount(publicKey: string, notify: ManageDataNotifier): Promise<number> {
  const cursorKey = `${CURSOR_KEY_PREFIX}${publicKey}`;
  const stateKey = `${STATE_KEY_PREFIX}${publicKey}`;
  const [cursor, rawState] = await Promise.all([redisCache.get(cursorKey), redisCache.get(stateKey)]);

  if (!cursor || !rawState) {
    await seedAccount(publicKey);
    return 0;
  }

  const result = await stellar.getAccountOperationsSince(publicKey, cursor, OPERATIONS_PAGE_SIZE);
  if (!result.ok) return 0;

  const state = parseState(rawState);
  let emitted = 0;

  for (const record of result.records as ManageDataOperation[]) {
    // The account's feed also lists operations it merely participated in;
    // a data entry always belongs to the operation's source account.
    if (record.type === 'manage_data' && record.source_account === publicKey) {
      const alert = diffManageData(record, state);
      if (alert) {
        const dedupeKey = `${ALERT_KEY_PREFIX}${alert.operationId}:${alert.account}`;
        if (await redisCache.setNx(dedupeKey, '1', ALERT_DEDUPE_TTL_SECONDS)) {
          log.warn(`[${alert.severity}] ${alert.message}`);
          try {
            await notify(alert);
            emitted += 1;
          } catch (err: unknown) {
            // Release the claim and leave the cursor so the next pass retries.
            await redisCache.del(dedupeKey);
            throw err;
          }
        }
      }
      applyManageData(record, state);
      await redisCache.set(stateKey, serializeState(state));
    }
    if (record.paging_token) await redisCache.set(cursorKey, record.paging_token);
  }

  return emitted;
}

/** One pass over the monitored accounts; each account's failure is isolated. */
export async function runManageDataSentinelPass(
  publicKeys: string[],
  notify: ManageDataNotifier = deliverManageDataAlert,
): Promise<number> {
  let emitted = 0;
  for (const publicKey of new Set(publicKeys)) {
    try {
      emitted += await scanAccount(publicKey, notify);
    } catch (err: unknown) {
      log.warn(`Data entry scan failed for ${short(publicKey)}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return emitted;
}
