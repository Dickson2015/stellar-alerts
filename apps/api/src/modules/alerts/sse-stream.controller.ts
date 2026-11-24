import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import {
  authenticateHook,
  authenticateToken,
} from '../../middleware/auth.middleware';
import { AuthenticationError } from '../../lib/errors';
import { createLogger } from '../../lib/logger';
import { prisma } from '../../lib/prisma';
import { getRedisClient, registerRedisCleanupTask } from '../../lib/redis';
import {
  REALTIME_CHANNELS,
  type AlertStreamEvent,
} from '../../lib/realtime';

const log = createLogger({ module: 'SseAlertStream' });

/** 1,000 events per tenant is the bounded replay window from issue #1038. */
export const MAX_REPLAY_EVENTS = 1000;
export const HEARTBEAT_INTERVAL_MS = 15_000;

const SSE_HEADERS: Record<string, string> = {
  'Content-Type': 'text/event-stream',
  'Cache-Control': 'no-cache',
  Connection: 'keep-alive',
  'X-Accel-Buffering': 'no',
};

export interface StreamFilters {
  severities: string[];
  walletId?: string;
  lastEventId?: string;
}

function firstQueryValue(value: unknown): string | undefined {
  if (Array.isArray(value)) return typeof value[0] === 'string' ? value[0] : undefined;
  return typeof value === 'string' ? value : undefined;
}

/** Parses the query-string filters evaluated independently for each connection. */
export function parseStreamFilters(
  query: Record<string, unknown> = {},
  lastEventIdHeader?: string,
): StreamFilters {
  const severity = firstQueryValue(query.severity);
  return {
    severities: severity
      ? severity.split(',').map((entry) => entry.trim().toUpperCase()).filter(Boolean)
      : [],
    walletId: firstQueryValue(query.walletId) || undefined,
    lastEventId: lastEventIdHeader || firstQueryValue(query.lastEventId) || undefined,
  };
}

export function eventMatchesFilters(event: AlertStreamEvent, filters: StreamFilters): boolean {
  if (filters.severities.length > 0) {
    const severity = String(event.severity ?? '').toUpperCase();
    if (!filters.severities.includes(severity)) return false;
  }
  if (filters.walletId && event.walletId !== filters.walletId) return false;
  return true;
}

/** SSE wire format: id/event/data followed by a blank line. */
export function formatAlertFrame(event: AlertStreamEvent): string {
  return [
    `id: ${event.id}`,
    `event: ${event.event || 'alert'}`,
    `data: ${JSON.stringify(event)}`,
    '',
    '',
  ].join('\n');
}

function parseEventId(id: string): { time: number; sequence: number } {
  const [time, sequence] = id.split('-');
  const parsedTime = Number(time);
  const parsedSequence = Number(sequence);
  return {
    time: Number.isFinite(parsedTime) ? parsedTime : 0,
    sequence: Number.isFinite(parsedSequence) ? parsedSequence : 0,
  };
}

function compareEventIds(left: string, right: string): number {
  const a = parseEventId(left);
  const b = parseEventId(right);
  return a.time - b.time || a.sequence - b.sequence;
}

/**
 * Per-tenant bounded replay buffer plus local fan-out. Cross-pod events arrive
 * through the Redis channel; ingest() de-duplicates the local copy that was
 * published in the same process.
 */
export class AlertStreamHub {
  private readonly buffers = new Map<string, AlertStreamEvent[]>();
  private readonly listeners = new Map<string, Set<(event: AlertStreamEvent) => void>>();
  private sequence = 0;
  private subscriber: Promise<void> | null = null;

  /** Returns false for an already-buffered event, so Redis echo is harmless. */
  ingest(event: AlertStreamEvent): boolean {
    if (!event?.id || !event.userId) return false;

    const buffer = this.buffers.get(event.userId) ?? [];
    if (buffer.some((existing) => existing.id === event.id)) return false;

    buffer.push(event);
    if (buffer.length > MAX_REPLAY_EVENTS) {
      buffer.splice(0, buffer.length - MAX_REPLAY_EVENTS);
    }
    this.buffers.set(event.userId, buffer);

    for (const listener of this.listeners.get(event.userId) ?? []) {
      try {
        listener(event);
      } catch (err: unknown) {
        log.warn(`SSE listener failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    return true;
  }

  /** Local event ID generator shared with tests and the publisher. */
  nextId(): string {
    return `${Date.now()}-${++this.sequence}`;
  }

  subscribe(
    userId: string,
    listener: (event: AlertStreamEvent) => void,
  ): () => void {
    let clients = this.listeners.get(userId);
    if (!clients) {
      clients = new Set();
      this.listeners.set(userId, clients);
    }
    clients.add(listener);
    return () => {
      clients.delete(listener);
      if (clients.size === 0) this.listeners.delete(userId);
    };
  }

  /** Every buffered event after Last-Event-ID, in original order. */
  replay(userId: string, lastEventId?: string): AlertStreamEvent[] {
    const buffer = this.buffers.get(userId) ?? [];
    if (!lastEventId) return [...buffer];

    const exact = buffer.findIndex((event) => event.id === lastEventId);
    if (exact >= 0) return buffer.slice(exact + 1);
    return buffer.filter((event) => compareEventIds(event.id, lastEventId) > 0);
  }

  bufferedCount(userId: string): number {
    return this.buffers.get(userId)?.length ?? 0;
  }

  /** Starts the Redis bridge once; failures degrade to in-process fan-out. */
  startRedisSubscriber(): Promise<void> {
    if (this.subscriber) return this.subscriber;

    this.subscriber = (async () => {
      try {
        const client = getRedisClient().duplicate();
        registerRedisCleanupTask(async () => {
          await client.quit();
        });
        client.on('message', (channel: string, message: string) => {
          if (channel !== REALTIME_CHANNELS.ALERTS) return;
          try {
            this.ingest(JSON.parse(message) as AlertStreamEvent);
          } catch (err: unknown) {
            log.warn(`Invalid alert stream message: ${err instanceof Error ? err.message : String(err)}`);
          }
        });
        await client.subscribe(REALTIME_CHANNELS.ALERTS);
      } catch (err: unknown) {
        this.subscriber = null;
        log.warn(`Alert stream Redis subscriber unavailable: ${err instanceof Error ? err.message : String(err)}`);
      }
    })();

    return this.subscriber;
  }
}

export const alertStreamHub = new AlertStreamHub();

/** Minimal request/reply surface needed by the stream handler. */
export interface StreamRequestLike {
  user?: { id: string };
  headers: Record<string, string | string[] | undefined>;
  query: Record<string, unknown>;
  raw: {
    on(event: string, listener: () => void): unknown;
  };
}

export interface StreamReplyLike {
  hijack(): void;
  raw: {
    writeHead(status: number, headers: Record<string, string>): unknown;
    write(chunk: string): unknown;
  };
  status?(code: number): StreamReplyLike;
  send?(body: unknown): StreamReplyLike;
}

export interface StreamHandlerOptions {
  hub?: AlertStreamHub;
  heartbeatMs?: number;
  validateWalletOwnership?: (userId: string, walletId: string) => Promise<boolean>;
}

const defaultValidateWalletOwnership = async (userId: string, walletId: string): Promise<boolean> => {
  const wallet = await prisma.wallet.findFirst({
    where: { id: walletId, userId, deletedAt: null },
    select: { id: true },
  });
  return Boolean(wallet);
};

/**
 * Authenticated SSE handler. Replays missed events before registering the live
 * listener, then sends 15-second heartbeat comments until the client disconnects.
 */
export async function handleAlertStream(
  request: StreamRequestLike,
  reply: StreamReplyLike,
  options: StreamHandlerOptions = {},
): Promise<void> {
  const userId = request.user?.id;
  if (!userId) {
    reply.status?.(401).send?.({ error: 'Authentication required' });
    return;
  }

  const hub = options.hub ?? alertStreamHub;
  const filters = parseStreamFilters(
    request.query,
    typeof request.headers['last-event-id'] === 'string' ? request.headers['last-event-id'] : undefined,
  );

  if (filters.walletId) {
    const ownsWallet = await (options.validateWalletOwnership ?? defaultValidateWalletOwnership)(
      userId,
      filters.walletId,
    );
    if (!ownsWallet) {
      reply.status?.(403).send?.({ error: 'Wallet does not belong to this user' });
      return;
    }
  }

  reply.hijack();
  reply.raw.writeHead(200, SSE_HEADERS);
  reply.raw.write('event: connected\ndata: {"status":"connected"}\n\n');

  const send = (event: AlertStreamEvent) => {
    if (!eventMatchesFilters(event, filters)) return;
    reply.raw.write(formatAlertFrame(event));
  };

  const unsubscribe = hub.subscribe(userId, send);
  for (const event of hub.replay(userId, filters.lastEventId)) send(event);

  const heartbeat = setInterval(() => reply.raw.write(': heartbeat\n\n'), options.heartbeatMs ?? HEARTBEAT_INTERVAL_MS);
  heartbeat.unref?.();

  const cleanup = () => {
    clearInterval(heartbeat);
    unsubscribe();
  };
  request.raw.on('close', cleanup);

  await new Promise<void>((resolve) => {
    request.raw.on('close', resolve);
  });
}

/** EventSource cannot set Authorization headers, so a short-lived token query is also accepted. */
async function sseAuthenticate(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  if (request.headers.authorization) {
    await authenticateHook(request, reply);
    return;
  }

  const token = (request.query as { token?: unknown } | undefined)?.token;
  if (typeof token !== 'string' || token.length === 0) {
    throw new AuthenticationError('You must be logged in to perform this action.', 'AUTH_REQUIRED');
  }
  await authenticateToken(request, reply, token);
}

export interface SseRouteOptions {
  hub?: AlertStreamHub;
  startRedisSubscriber?: boolean;
  authenticate?: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  validateWalletOwnership?: (userId: string, walletId: string) => Promise<boolean>;
}

/** GET /alerts/stream, registered under the /api/v1 prefix in app.ts. */
export async function registerSseAlertStreamRoutes(
  app: FastifyInstance,
  options: SseRouteOptions = {},
): Promise<void> {
  const hub = options.hub ?? alertStreamHub;
  if (options.startRedisSubscriber !== false) void hub.startRedisSubscriber();

  app.get(
    '/alerts/stream',
    {
      preHandler: [options.authenticate ?? sseAuthenticate],
      config: { rateLimit: { max: 30, timeWindow: '1 minute' } },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      await handleAlertStream(
        request as unknown as StreamRequestLike,
        reply as unknown as StreamReplyLike,
        { hub, validateWalletOwnership: options.validateWalletOwnership },
      );
    },
  );
}
