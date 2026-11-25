import { describe, it, expect, vi } from 'vitest';
import {
  MatrixDispatcher,
  buildMatrixSendUrl,
  formatMatrixAlertPayload,
  generateDeterministicTxnId,
  isValidMatrixRoomId,
  parseMatrixRateLimit,
  type MatrixAlertPayload,
  type MatrixDispatchTarget,
  type MatrixFetchFn,
  type MatrixHttpResponse,
} from '../matrix.dispatcher';

const SAMPLE_TARGET: MatrixDispatchTarget = {
  homeserverUrl: 'https://matrix.example.org/',
  roomId: '!secOpsRoom123:matrix.example.org',
  accessToken: 'syt_test_access_token_12345',
};

const SAMPLE_ALERT: MatrixAlertPayload = {
  alertId: 'pay-987654',
  title: 'Large Incoming Payment Detected',
  severity: 'critical',
  message: 'Incoming transfer exceeded configured threshold.',
  amount: '5000',
  asset: 'XLM',
  fromAddress: 'GDQP2KPQGKIHYJGXNUIYOMHARUARCA7DJT5FO2FFOOKY3B2WSFMG4BVI',
  txHash: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
  memo: 'treasury-settlement',
  network: 'public',
  receivedAt: '2026-11-24T17:00:00.000Z',
  dashboardUrl: 'https://stellar-alerts.com/alerts/pay-987654',
};

describe('Matrix payload formatter (#1003)', () => {
  it('builds both plain-text fallback body and rich org.matrix.custom.html card', () => {
    const content = formatMatrixAlertPayload(SAMPLE_ALERT);

    expect(content.msgtype).toBe('m.notice');
    expect(content.format).toBe('org.matrix.custom.html');

    // Plain-text fallback
    expect(content.body).toContain('[CRITICAL] Large Incoming Payment Detected');
    expect(content.body).toContain('Amount: 5000 XLM');
    expect(content.body).toContain(`From: ${SAMPLE_ALERT.fromAddress}`);
    expect(content.body).toContain(`Tx Hash: ${SAMPLE_ALERT.txHash}`);
    expect(content.body).toContain('Memo: treasury-settlement');
    expect(content.body).toContain(`https://stellar.expert/explorer/public/tx/${SAMPLE_ALERT.txHash}`);

    // Rich HTML formatted card
    expect(content.formatted_body).toContain('<h4>[CRITICAL] Large Incoming Payment Detected</h4>');
    expect(content.formatted_body).toContain('<blockquote>Incoming transfer exceeded configured threshold.</blockquote>');
    expect(content.formatted_body).toContain('<code>5000 XLM</code>');
    expect(content.formatted_body).toContain('View on Stellar Explorer');
    expect(content.formatted_body).toContain('Open in Dashboard');
  });

  it('escapes HTML special characters in user/transaction fields', () => {
    const content = formatMatrixAlertPayload({
      alertId: 'pay-xss',
      title: 'Alert <script>alert(1)</script>',
      message: 'Memo & "details" with <img src=x>',
      memo: '<b>unsafe</b>',
    });

    expect(content.formatted_body).not.toContain('<script>');
    expect(content.formatted_body).not.toContain('<img');
    expect(content.formatted_body).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(content.formatted_body).toContain('&amp; &quot;details&quot;');
    expect(content.formatted_body).toContain('&lt;b&gt;unsafe&lt;/b&gt;');
  });
});

describe('Idempotent txnId & Matrix Client-Server API URL generation (#1003)', () => {
  it('generates deterministic txnId across retries for the same room and event key', () => {
    const first = generateDeterministicTxnId({
      roomId: SAMPLE_TARGET.roomId,
      eventKey: SAMPLE_ALERT.alertId,
      namespace: 'alert',
    });
    const second = generateDeterministicTxnId({
      roomId: SAMPLE_TARGET.roomId,
      eventKey: SAMPLE_ALERT.alertId,
      namespace: 'alert',
    });
    const differentAlert = generateDeterministicTxnId({
      roomId: SAMPLE_TARGET.roomId,
      eventKey: 'pay-other',
      namespace: 'alert',
    });
    const differentRoom = generateDeterministicTxnId({
      roomId: '!otherRoom:matrix.org',
      eventKey: SAMPLE_ALERT.alertId,
      namespace: 'alert',
    });

    expect(first).toBe(second);
    expect(first).toMatch(/^sa_[a-f0-9]{32}$/);
    expect(first).not.toBe(differentAlert);
    expect(first).not.toBe(differentRoom);
  });

  it('builds properly encoded /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId} URL', () => {
    const txnId = 'sa_0123456789abcdef0123456789abcdef';
    const url = buildMatrixSendUrl(
      'https://matrix.example.org///',
      '!secOpsRoom123:matrix.example.org',
      txnId,
    );

    expect(url).toBe(
      'https://matrix.example.org/_matrix/client/v3/rooms/!secOpsRoom123%3Amatrix.example.org/send/m.room.message/sa_0123456789abcdef0123456789abcdef',
    );
  });

  it('validates Matrix room IDs', () => {
    expect(isValidMatrixRoomId('!abc123:matrix.org')).toBe(true);
    expect(isValidMatrixRoomId('#alias:matrix.org')).toBe(false);
    expect(isValidMatrixRoomId('not-a-room')).toBe(false);
    expect(isValidMatrixRoomId('')).toBe(false);
  });
});

describe('MatrixDispatcher 429 M_LIMIT_EXCEEDED & interactive reactions (#1003)', () => {
  it('dispatches formatted alert via PUT with Bearer token and sends interactive reactions', async () => {
    const calls: Array<{ url: string; method: string; auth: string; body: Record<string, unknown> }> = [];
    let callCount = 0;

    const fetchFn: MatrixFetchFn = vi.fn(async (url, init) => {
      callCount++;
      calls.push({
        url,
        method: init.method,
        auth: init.headers.Authorization,
        body: JSON.parse(init.body) as Record<string, unknown>,
      });
      return {
        status: 200,
        body: JSON.stringify({ event_id: `$event_${callCount}` }),
      };
    });

    const dispatcher = new MatrixDispatcher({
      fetchFn,
      sleepFn: vi.fn(async () => undefined),
    });

    const result = await dispatcher.dispatchAlert(
      { ...SAMPLE_TARGET, reactions: ['✅', '🔕'] },
      SAMPLE_ALERT,
    );

    expect(result.success).toBe(true);
    expect(result.statusCode).toBe(200);
    expect(result.eventId).toBe('$event_1');
    expect(result.attempts).toBe(1);
    expect(result.reactionEventIds).toEqual(['$event_2', '$event_3']);

    expect(calls).toHaveLength(3);
    expect(calls[0].method).toBe('PUT');
    expect(calls[0].auth).toBe(`Bearer ${SAMPLE_TARGET.accessToken}`);
    expect(calls[0].url).toContain('/_matrix/client/v3/rooms/!secOpsRoom123%3Amatrix.example.org/send/m.room.message/');
    expect(calls[0].body.format).toBe('org.matrix.custom.html');

    // Interactive reactions reference the posted alert event_id
    expect(calls[1].url).toContain('/send/m.reaction/');
    expect(calls[1].body).toEqual({
      'm.relates_to': {
        rel_type: 'm.annotation',
        event_id: '$event_1',
        key: '✅',
      },
    });
    expect(calls[2].body).toEqual({
      'm.relates_to': {
        rel_type: 'm.annotation',
        event_id: '$event_1',
        key: '🔕',
      },
    });
  });

  it('respects 429 M_LIMIT_EXCEEDED retry_after_ms and retries with the exact same idempotent txnId', async () => {
    const requestedUrls: string[] = [];
    const sleepCalls: number[] = [];

    const responses: MatrixHttpResponse[] = [
      {
        status: 429,
        body: JSON.stringify({
          errcode: 'M_LIMIT_EXCEEDED',
          error: 'Too Many Requests',
          retry_after_ms: 2500,
        }),
      },
      {
        status: 200,
        body: JSON.stringify({ event_id: '$ev_after_retry' }),
      },
    ];

    const fetchFn: MatrixFetchFn = vi.fn(async (url) => {
      requestedUrls.push(url);
      return responses.shift()!;
    });

    const sleepFn = vi.fn(async (ms: number) => {
      sleepCalls.push(ms);
    });

    const dispatcher = new MatrixDispatcher({
      fetchFn,
      sleepFn,
      maxRetries: 2,
    });

    const result = await dispatcher.dispatchAlert(SAMPLE_TARGET, SAMPLE_ALERT);

    expect(result.success).toBe(true);
    expect(result.eventId).toBe('$ev_after_retry');
    expect(result.attempts).toBe(2);
    expect(sleepCalls).toEqual([2500]);
    expect(requestedUrls).toHaveLength(2);
    // Exact same URL and txnId across retries guarantees idempotency
    expect(requestedUrls[0]).toBe(requestedUrls[1]);
  });

  it('returns rateLimited metadata after exhausting retries on persistent 429 responses', async () => {
    const sleepCalls: number[] = [];
    const fetchFn: MatrixFetchFn = vi.fn(async () => ({
      status: 429,
      body: JSON.stringify({
        errcode: 'M_LIMIT_EXCEEDED',
        error: 'Rate limit exceeded',
        retry_after_ms: 45000,
      }),
    }));

    const dispatcher = new MatrixDispatcher({
      fetchFn,
      sleepFn: vi.fn(async (ms: number) => {
        sleepCalls.push(ms);
      }),
      maxRetries: 2,
      maxRetryAfterMs: 10_000,
    });

    const result = await dispatcher.dispatchAlert(SAMPLE_TARGET, SAMPLE_ALERT);

    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(429);
    expect(result.rateLimited).toBe(true);
    expect(result.errorCode).toBe('M_LIMIT_EXCEEDED');
    expect(result.retryAfterMs).toBe(45000);
    expect(result.attempts).toBe(3); // initial + 2 retries
    // Sleep is capped at maxRetryAfterMs
    expect(sleepCalls).toEqual([10_000, 10_000]);
  });

  it('parses Retry-After header fallback when JSON retry_after_ms is absent', () => {
    const parsed = parseMatrixRateLimit({
      status: 429,
      body: JSON.stringify({ errcode: 'M_LIMIT_EXCEEDED' }),
      headers: {
        get: (name: string) => (name.toLowerCase() === 'retry-after' ? '4' : null),
      },
    });
    expect(parsed.errorCode).toBe('M_LIMIT_EXCEEDED');
    expect(parsed.retryAfterMs).toBe(4000);
  });

  it('rejects invalid Matrix room IDs without issuing an HTTP request', async () => {
    const fetchFn: MatrixFetchFn = vi.fn();
    const dispatcher = new MatrixDispatcher({ fetchFn });

    const result = await dispatcher.dispatchAlert(
      { ...SAMPLE_TARGET, roomId: 'invalid-room-id' },
      SAMPLE_ALERT,
    );

    expect(result.success).toBe(false);
    expect(result.attempts).toBe(0);
    expect(result.error).toContain('Invalid Matrix room ID');
    expect(fetchFn).not.toHaveBeenCalled();
  });
});
