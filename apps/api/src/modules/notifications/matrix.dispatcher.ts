/**
 * Matrix Protocol Encrypted Room Bot Dispatcher with Interactive Alert Reactions (#1003).
 *
 * Implements a native Matrix Client-Server API v3 notification provider:
 * - Posts both plain-text fallback (`body`) and rich `org.matrix.custom.html` formatted
 *   alert cards to self-hosted or federated Matrix rooms.
 * - Uses deterministic SHA-256 event transaction IDs (`txnId`) in the PUT endpoint
 *   `/_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}` to guarantee
 *   idempotent message delivery across retries.
 * - Respects Matrix homeserver rate-limit responses (`429` with `M_LIMIT_EXCEEDED` and
 *   `retry_after_ms`) with bounded automatic retry.
 * - Supports interactive alert reaction annotations (`m.reaction` / `m.annotation`, MSC2677).
 */

import crypto from 'node:crypto';
import { createLogger } from '../../lib/logger';

const log = createLogger({ module: 'MatrixDispatcher' });

export const DEFAULT_MATRIX_MAX_RETRIES = 3;
export const DEFAULT_MATRIX_RETRY_AFTER_MS = 1000;
export const DEFAULT_MATRIX_MAX_RETRY_AFTER_MS = 30_000;
export const DEFAULT_MATRIX_TIMEOUT_MS = 10_000;

export interface MatrixDispatchTarget {
  /** Base URL of the Matrix homeserver, e.g. `https://matrix.org` or `https://matrix.example.org` */
  homeserverUrl: string;
  /** Target Matrix room ID, e.g. `!abcdef123456:matrix.org` */
  roomId: string;
  /** Bot access token (Bearer token) */
  accessToken: string;
  /** Message type: `m.notice` (default for bots) or `m.text` */
  msgtype?: 'm.notice' | 'm.text';
  /** Optional interactive reaction emojis to attach after posting the alert card (e.g. ['✅', '🔕']) */
  reactions?: string[];
}

export interface MatrixAlertPayload {
  /** Unique alert/payment identifier used to derive the deterministic `txnId` */
  alertId: string;
  title?: string;
  severity?: 'critical' | 'high' | 'warning' | 'info' | string;
  message?: string;
  txHash?: string;
  amount?: string | number;
  asset?: string;
  fromAddress?: string;
  walletId?: string;
  memo?: string | null;
  network?: 'public' | 'testnet' | string;
  receivedAt?: string | Date;
  explorerUrl?: string;
  dashboardUrl?: string;
}

export interface MatrixMessageContent {
  msgtype: 'm.notice' | 'm.text';
  body: string;
  format: 'org.matrix.custom.html';
  formatted_body: string;
}

export interface MatrixReactionContent {
  'm.relates_to': {
    rel_type: 'm.annotation';
    event_id: string;
    key: string;
  };
}

export interface MatrixRateLimitBody {
  errcode?: string;
  error?: string;
  retry_after_ms?: number;
}

export interface MatrixHttpResponse {
  status: number;
  body: string;
  headers?: {
    get(name: string): string | null;
  };
}

export type MatrixFetchFn = (
  url: string,
  init: {
    method: 'PUT';
    headers: Record<string, string>;
    body: string;
    signal?: AbortSignal;
  },
) => Promise<MatrixHttpResponse>;

export type SleepFn = (ms: number) => Promise<void>;

export interface MatrixDispatcherOptions {
  fetchFn?: MatrixFetchFn;
  sleepFn?: SleepFn;
  maxRetries?: number;
  maxRetryAfterMs?: number;
  timeoutMs?: number;
}

export interface MatrixDispatchResult {
  success: boolean;
  statusCode?: number;
  eventId?: string;
  txnId: string;
  url: string;
  attempts: number;
  rateLimited?: boolean;
  retryAfterMs?: number;
  errorCode?: string;
  error?: string;
  reactionEventIds?: string[];
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function truncateMiddle(value: string, head = 8, tail = 6): string {
  if (value.length <= head + tail + 3) return value;
  return `${value.slice(0, head)}...${value.slice(-tail)}`;
}

/**
 * Validates a Matrix room ID (`!<opaque_id>:<server_name>`).
 */
export function isValidMatrixRoomId(roomId: string): boolean {
  const trimmed = roomId.trim();
  return trimmed.startsWith('!') && trimmed.includes(':') && trimmed.length >= 5;
}

/**
 * Normalizes a Matrix homeserver URL by stripping trailing slashes.
 */
export function normalizeHomeserverUrl(homeserverUrl: string): string {
  const parsed = new URL(homeserverUrl.trim());
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error(`Unsupported Matrix homeserver protocol: ${parsed.protocol}`);
  }
  return parsed.toString().replace(/\/+$/, '');
}

/**
 * Generates a deterministic, URL-safe transaction ID (`txnId`) for idempotent
 * Matrix Client-Server API event submission across retries.
 */
export function generateDeterministicTxnId(params: {
  roomId: string;
  eventKey: string;
  namespace?: string;
}): string {
  const namespace = params.namespace ?? 'msg';
  const digest = crypto
    .createHash('sha256')
    .update(`${namespace}:${params.roomId.trim()}:${params.eventKey.trim()}`)
    .digest('hex');
  return `sa_${digest.slice(0, 32)}`;
}

/**
 * Constructs the Matrix Client-Server API v3 event send URL:
 * `{homeserverUrl}/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}`
 */
export function buildMatrixSendUrl(
  homeserverUrl: string,
  roomId: string,
  txnId: string,
  eventType: 'm.room.message' | 'm.reaction' = 'm.room.message',
): string {
  const base = normalizeHomeserverUrl(homeserverUrl);
  return (
    `${base}/_matrix/client/v3/rooms/${encodeURIComponent(roomId.trim())}` +
    `/send/${encodeURIComponent(eventType)}/${encodeURIComponent(txnId)}`
  );
}

/**
 * Formats a Stellar Alerts event into both plain-text fallback (`body`) and
 * rich `org.matrix.custom.html` (`formatted_body`) Matrix message content.
 */
export function formatMatrixAlertPayload(
  alert: MatrixAlertPayload,
  msgtype: 'm.notice' | 'm.text' = 'm.notice',
): MatrixMessageContent {
  const severity = (alert.severity ?? 'info').toUpperCase();
  const title = alert.title ?? 'Stellar Alerts Notification';
  const network = alert.network ?? 'public';
  const explorerBase =
    network === 'testnet'
      ? 'https://stellar.expert/explorer/testnet'
      : 'https://stellar.expert/explorer/public';
  const explorerUrl =
    alert.explorerUrl ?? (alert.txHash ? `${explorerBase}/tx/${alert.txHash}` : undefined);
  const timestamp = alert.receivedAt
    ? new Date(alert.receivedAt).toISOString()
    : undefined;

  const plainLines: string[] = [`[${severity}] ${title}`];
  if (alert.message) plainLines.push(alert.message);
  if (alert.amount !== undefined && alert.asset) {
    plainLines.push(`Amount: ${alert.amount} ${alert.asset}`);
  }
  if (alert.fromAddress) {
    plainLines.push(`From: ${alert.fromAddress}`);
  }
  if (alert.txHash) {
    plainLines.push(`Tx Hash: ${alert.txHash}`);
  }
  if (alert.memo) {
    plainLines.push(`Memo: ${alert.memo}`);
  }
  if (timestamp) {
    plainLines.push(`Time: ${timestamp}`);
  }
  if (explorerUrl) {
    plainLines.push(`Explorer: ${explorerUrl}`);
  }
  if (alert.dashboardUrl) {
    plainLines.push(`Dashboard: ${alert.dashboardUrl}`);
  }

  const htmlRows: string[] = [];
  if (alert.amount !== undefined && alert.asset) {
    htmlRows.push(
      `<li><strong>Amount:</strong> <code>${escapeHtml(String(alert.amount))} ${escapeHtml(alert.asset)}</code></li>`,
    );
  }
  if (alert.fromAddress) {
    htmlRows.push(
      `<li><strong>From:</strong> <code>${escapeHtml(truncateMiddle(alert.fromAddress))}</code></li>`,
    );
  }
  if (alert.txHash) {
    htmlRows.push(
      `<li><strong>Tx Hash:</strong> <code>${escapeHtml(truncateMiddle(alert.txHash))}</code></li>`,
    );
  }
  if (alert.memo) {
    htmlRows.push(`<li><strong>Memo:</strong> ${escapeHtml(alert.memo)}</li>`);
  }
  if (timestamp) {
    htmlRows.push(`<li><strong>Time:</strong> ${escapeHtml(timestamp)}</li>`);
  }

  const links: string[] = [];
  if (explorerUrl) {
    links.push(`<a href="${escapeHtml(explorerUrl)}">View on Stellar Explorer</a>`);
  }
  if (alert.dashboardUrl) {
    links.push(`<a href="${escapeHtml(alert.dashboardUrl)}">Open in Dashboard</a>`);
  }

  const htmlParts: string[] = [
    `<h4>[${escapeHtml(severity)}] ${escapeHtml(title)}</h4>`,
  ];
  if (alert.message) {
    htmlParts.push(`<blockquote>${escapeHtml(alert.message)}</blockquote>`);
  }
  if (htmlRows.length > 0) {
    htmlParts.push(`<ul>${htmlRows.join('')}</ul>`);
  }
  if (links.length > 0) {
    htmlParts.push(`<p>${links.join(' &middot; ')}</p>`);
  }

  return {
    msgtype,
    body: plainLines.join('\n'),
    format: 'org.matrix.custom.html',
    formatted_body: htmlParts.join(''),
  };
}

/**
 * Parses `retry_after_ms` from a Matrix 429 (`M_LIMIT_EXCEEDED`) response.
 */
export function parseMatrixRateLimit(
  response: MatrixHttpResponse,
): { errorCode?: string; retryAfterMs: number; errorMessage?: string } {
  let parsed: MatrixRateLimitBody | null = null;
  if (response.body) {
    try {
      parsed = JSON.parse(response.body) as MatrixRateLimitBody;
    } catch {
      parsed = null;
    }
  }

  if (parsed && typeof parsed.retry_after_ms === 'number' && Number.isFinite(parsed.retry_after_ms) && parsed.retry_after_ms >= 0) {
    return {
      errorCode: parsed.errcode ?? 'M_LIMIT_EXCEEDED',
      retryAfterMs: parsed.retry_after_ms,
      errorMessage: parsed.error,
    };
  }

  const retryAfterHeader = response.headers?.get('retry-after');
  if (retryAfterHeader) {
    const seconds = Number(retryAfterHeader);
    if (Number.isFinite(seconds) && seconds >= 0) {
      return {
        errorCode: parsed?.errcode ?? 'M_LIMIT_EXCEEDED',
        retryAfterMs: Math.round(seconds * 1000),
        errorMessage: parsed?.error,
      };
    }
  }

  return {
    errorCode: parsed?.errcode ?? 'M_LIMIT_EXCEEDED',
    retryAfterMs: DEFAULT_MATRIX_RETRY_AFTER_MS,
    errorMessage: parsed?.error,
  };
}

async function defaultFetch(
  url: string,
  init: {
    method: 'PUT';
    headers: Record<string, string>;
    body: string;
    signal?: AbortSignal;
  },
): Promise<MatrixHttpResponse> {
  const res = await fetch(url, init);
  return {
    status: res.status,
    body: await res.text(),
    headers: res.headers,
  };
}

const defaultSleep: SleepFn = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));

export class MatrixDispatcher {
  private readonly fetchFn: MatrixFetchFn;
  private readonly sleepFn: SleepFn;
  private readonly maxRetries: number;
  private readonly maxRetryAfterMs: number;
  private readonly timeoutMs: number;

  constructor(options: MatrixDispatcherOptions = {}) {
    this.fetchFn = options.fetchFn ?? defaultFetch;
    this.sleepFn = options.sleepFn ?? defaultSleep;
    this.maxRetries = options.maxRetries ?? DEFAULT_MATRIX_MAX_RETRIES;
    this.maxRetryAfterMs = options.maxRetryAfterMs ?? DEFAULT_MATRIX_MAX_RETRY_AFTER_MS;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_MATRIX_TIMEOUT_MS;
  }

  /**
   * Dispatches a formatted alert card to a Matrix room using an idempotent
   * deterministic `txnId`, automatically respecting `429 M_LIMIT_EXCEEDED`
   * `retry_after_ms` rate-limit responses.
   */
  public async dispatchAlert(
    target: MatrixDispatchTarget,
    alert: MatrixAlertPayload,
  ): Promise<MatrixDispatchResult> {
    if (!isValidMatrixRoomId(target.roomId)) {
      const txnId = generateDeterministicTxnId({
        roomId: target.roomId || 'invalid',
        eventKey: alert.alertId,
      });
      return {
        success: false,
        txnId,
        url: '',
        attempts: 0,
        error: `Invalid Matrix room ID: ${target.roomId}`,
      };
    }

    const txnId = generateDeterministicTxnId({
      roomId: target.roomId,
      eventKey: alert.alertId,
      namespace: 'alert',
    });
    const url = buildMatrixSendUrl(target.homeserverUrl, target.roomId, txnId, 'm.room.message');
    const content = formatMatrixAlertPayload(alert, target.msgtype ?? 'm.notice');

    const sendResult = await this.putEventWithRateLimitRetry(
      url,
      target.accessToken,
      txnId,
      content,
    );

    if (sendResult.success && sendResult.eventId && target.reactions && target.reactions.length > 0) {
      const reactionEventIds: string[] = [];
      for (const emoji of target.reactions) {
        const reactionResult = await this.sendReaction(
          target,
          sendResult.eventId,
          emoji,
          alert.alertId,
        );
        if (reactionResult.success && reactionResult.eventId) {
          reactionEventIds.push(reactionResult.eventId);
        }
      }
      sendResult.reactionEventIds = reactionEventIds;
    }

    return sendResult;
  }

  /**
   * Sends an interactive Matrix `m.reaction` annotation (MSC2677) referencing
   * an alert event ID using a deterministic `txnId`.
   */
  public async sendReaction(
    target: MatrixDispatchTarget,
    targetEventId: string,
    reactionKey: string,
    alertId: string,
  ): Promise<MatrixDispatchResult> {
    const txnId = generateDeterministicTxnId({
      roomId: target.roomId,
      eventKey: `${alertId}:${targetEventId}:${reactionKey}`,
      namespace: 'reaction',
    });
    const url = buildMatrixSendUrl(target.homeserverUrl, target.roomId, txnId, 'm.reaction');
    const content: MatrixReactionContent = {
      'm.relates_to': {
        rel_type: 'm.annotation',
        event_id: targetEventId,
        key: reactionKey,
      },
    };

    return this.putEventWithRateLimitRetry(url, target.accessToken, txnId, content);
  }

  private async putEventWithRateLimitRetry(
    url: string,
    accessToken: string,
    txnId: string,
    payload: MatrixMessageContent | MatrixReactionContent,
  ): Promise<MatrixDispatchResult> {
    const serialized = JSON.stringify(payload);
    let attempts = 0;

    while (attempts <= this.maxRetries) {
      attempts++;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const response = await this.fetchFn(url, {
          method: 'PUT',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: serialized,
          signal: controller.signal,
        });

        clearTimeout(timer);

        if (response.status >= 200 && response.status < 300) {
          let eventId: string | undefined;
          try {
            const data = JSON.parse(response.body) as { event_id?: string };
            eventId = data.event_id;
          } catch {
            // Non-JSON 2xx response
          }
          return {
            success: true,
            statusCode: response.status,
            eventId,
            txnId,
            url,
            attempts,
          };
        }

        if (response.status === 429) {
          const rateLimit = parseMatrixRateLimit(response);
          const boundedDelayMs = Math.min(rateLimit.retryAfterMs, this.maxRetryAfterMs);

          log.warn(
            {
              txnId,
              attempts,
              errorCode: rateLimit.errorCode,
              retryAfterMs: rateLimit.retryAfterMs,
              boundedDelayMs,
            },
            'Matrix homeserver returned 429 M_LIMIT_EXCEEDED',
          );

          if (attempts <= this.maxRetries) {
            await this.sleepFn(boundedDelayMs);
            continue;
          }

          return {
            success: false,
            statusCode: 429,
            txnId,
            url,
            attempts,
            rateLimited: true,
            retryAfterMs: rateLimit.retryAfterMs,
            errorCode: rateLimit.errorCode,
            error:
              rateLimit.errorMessage ??
              `Matrix rate limited (${rateLimit.errorCode}): retry after ${rateLimit.retryAfterMs}ms`,
          };
        }

        let errCode: string | undefined;
        let errMessage = `Matrix homeserver returned HTTP ${response.status}`;
        try {
          const errJson = JSON.parse(response.body) as MatrixRateLimitBody;
          errCode = errJson.errcode;
          if (errJson.error) errMessage = errJson.error;
        } catch {
          // Keep default error message
        }

        return {
          success: false,
          statusCode: response.status,
          txnId,
          url,
          attempts,
          errorCode: errCode,
          error: errMessage,
        };
      } catch (err: unknown) {
        clearTimeout(timer);
        const message = err instanceof Error ? err.message : String(err);
        log.error({ err: message, txnId, attempts }, 'Matrix dispatch request error');
        return {
          success: false,
          txnId,
          url,
          attempts,
          error: message,
        };
      }
    }

    return {
      success: false,
      txnId,
      url,
      attempts,
      error: 'Matrix dispatch failed after maximum retries',
    };
  }
}

export const matrixDispatcher = new MatrixDispatcher();
