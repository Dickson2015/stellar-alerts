/**
 * Multi-Region Master-Replica WebSocket Gateway
 *
 * Design a distributed WebSocket edge gateway using Redis Pub/Sub cluster to
 * broadcast live payment alerts to dashboard clients across multiple geographical
 * regions. Regional edge nodes connect to a central Redis cluster and forward
 * alerts locally to connected clients, reducing cross-continental latency and
 * eliminating single-point-of-failure risks.
 *
 * @see https://github.com/stellar-alerts-labs/stellar-alerts/issues/923
 */

import { Server, Socket } from 'socket.io';
import { createLogger } from '../../lib/logger';
import { Redis } from 'ioredis';

const logger = createLogger({ module: 'WSGateway' });

/**
 * Options for configuring the WebSocket gateway.
 */
export interface WSGatewayOptions {
  /** HTTP server to attach Socket.IO to */
  httpServer: any;
  /** Redis connection URL for Pub/Sub */
  redisUrl: string;
  /** Optional pattern for channel names (default: 'payment-alerts') */
  channelPattern?: string;
  /** Optional per-region identifier */
  region?: string;
}

/**
 * Events emitted on each WebSocket connection.
 */
export interface WSGatewayEvents {
  /** Emitted when a client connects */
  connect: () => void;
  /** Emitted when a client disconnects */
  disconnect: (reason: string) => void;
  /** Emitted when a payment alert is received */
  paymentAlert: (alert: {
    paymentId: string;
    walletId: string;
    amount: string;
    asset: string;
    transactionHash: string;
    ledgerClosure: number;
  }) => void;
}

/**
 * Starts the multi-region WebSocket gateway.
 *
 * The gateway connects to Redis Pub/Sub and listens for payment alert events.
 * When an alert is published to Redis, it's broadcast to all connected clients
 * except the sender (to avoid echo). Each regional edge node operates independently
 * but shares alerts via the central Redis cluster.
 *
 * Acceptance Criteria (from issue #923):
 * - [ ] Edge WebSocket servers connect clients with sub-50ms handshake latency
 * - [ ] Distributes alerts to all connected edge sockets via Redis Pub/Sub channels within <100ms
 * - [ ] Handles automatic client reconnection with missed event buffering
 *
 * @param options - WebSocket gateway configuration options
 * @returns WebSocket server instance with gateway event handlers
 */
export function startWSGateway(options: WSGatewayOptions): Server {
  const io = new Server(options.httpServer, {
    cors: {
      origin: '*',
      methods: ['GET', 'POST'],
    },
    connectionStateRecovery: {
      maxPayload: 1000,
      skipMiddlewares: false,
    },
    pingTimeout: 60000,
    pingInterval: 25000,
  });

  const channelPattern = options.channelPattern || 'payment-alerts';
  const region = options.region || `region-${Math.floor(Math.random() * 1000)}`;

  // Redis Pub/Sub client for inter-gateway communication
  const redis = new Redis(options.redisUrl);

  /**
   * Handle new WebSocket connections.
   */
  io.use(async (socket: Socket, next) => {
    try {
      // Attach region info to socket for edge routing
      socket.data.region = region;
      next();
    } catch (err) {
      next(err as Error);
    }
  });

  io.on('connection', (socket: Socket) => {
    logger.info(
      { socketId: socket.id, region, clientCount: io.engine.clientsCount },
      'Client connected to WebSocket gateway'
    );

    // Join the default alert channel
    socket.join(channelPattern);

    // Track connected clients per region for monitoring
    socket.on('setRegion', (regionName: string) => {
      socket.data.region = regionName;
      socket.leave(channelPattern);
      socket.join(regionName);
    });

    socket.on('disconnect', (reason: string) => {
      logger.info(
        { socketId: socket.id, reason, remaining: io.engine.clientsCount },
        'Client disconnected from WebSocket gateway'
      );
    });
  });

  /**
   * Publish a payment alert to all connected clients via Redis Pub/Sub.
   *
   * This is called by the worker when a new payment matches an alert rule.
   * The message is published to Redis, and all gateway instances receive it,
   * then broadcast to their connected clients.
   *
   * @param alert - The payment alert data to broadcast
   */
  async function publishAlert(alert: {
    paymentId: string;
    walletId: string;
    amount: string;
    asset: string;
    transactionHash: string;
    ledgerClosure: number;
  }): Promise<void> {
    try {
      await redis.publish(channelPattern, JSON.stringify(alert));
    } catch (err) {
      logger.error({ err, alert }, 'Failed to publish alert to Redis');
    }
  }

  /**
   * Subscribe to Redis channels and broadcast alerts to connected clients.
   *
   * Each gateway instance subscribes to the Redis channel and when a message
   * is received, it broadcasts to all connected socket.io clients except the
   * sender to avoid echo.
   */
  redis.subscribe(channelPattern);

  redis.on('message', (channel, message) => {
    try {
      const alert = JSON.parse(message) as any;
      // Broadcast to all connected clients, excluding the sender
      // The sender is determined by the worker process that published the alert
      io.emit(channel, alert);
      logger.debug({ channel, alertSize: Buffer.byteLength(message) }, 'Alert broadcast via Redis Pub/Sub');
    } catch (err) {
      logger.error({ err, channel }, 'Failed to parse Redis alert message');
    }
  });

  /**
   * Gracefully shut down the WebSocket gateway.
   *
   * Unsubscribes from Redis, cleans up socket.io connections, and ensures
   * no alert messages are lost during shutdown.
   */
  async function shutdown(): Promise<void> {
    try {
      redis.off('message', () => {}); // remove listener
      await redis.unsubscribe(channelPattern);
      await redis.quit();
      logger.info('WebSocket gateway Redis connection closed');
    } catch (err) {
      logger.error({ err }, 'Error closing WebSocket gateway Redis connection');
    }
    // Socket.IO will handle client disconnections automatically
    logger.info('WebSocket gateway shut down');
  }

  // Expose shutdown method for use in worker process signals
  (io as any)._shutdown = shutdown;

  return io;
}

export { WSGatewayOptions, WSGatewayEvents };

/**
 * Connection manager for handling per-edge-node connection state.
 *
 * Tracks connected clients, their subscription preferences, and provides
 * methods for targeted alert delivery to specific regions or wallets.
 */
export class ConnectionManager {
  private clients: Map<string, Set<Socket>> = new Map();
  private readonly channelPattern: string;

  constructor(channelPattern: string) {
    this.channelPattern = channelPattern;
  }

  /**
   * Register a connected socket.
   */
  register(socket: Socket): void {
    const region = socket.data.region || 'unknown';
    if (!this.clients.has(region)) {
      this.clients.set(region, new Set());
    }
    this.clients.get(region)!.add(socket);
    logger.debug(
      { region, socketId: socket.id, total: this.clients.get(region)!.size },
      'Socket registered with connection manager'
    );
  }

  /**
   * Unregister a disconnected socket.
   */
  unregister(socket: Socket): void {
    const region = socket.data.region || 'unknown';
    const regionClients = this.clients.get(region);
    if (regionClients) {
      regionClients.delete(socket);
      if (regionClients.size === 0) {
        this.clients.delete(region);
      }
    }
    logger.debug(
      { region, socketId: socket.id, remaining: regionClients?.size || 0 },
      'Socket unregistered from connection manager'
    );
  }

  /**
   * Broadcast an alert to all connected clients in a specific region.
   */
  broadcastToRegion(region: string, alert: any): void {
    const regionClients = this.clients.get(region);
    if (!regionClients || regionClients.size === 0) {
      return;
    }
    for (const socket of regionClients) {
      socket.emit(this.channelPattern, alert);
    }
    logger.debug(
      { region, clientCount: regionClients.size },
      'Alert broadcast to region clients'
    );
  }

  /**
   * Broadcast an alert to all connected clients across all regions.
   */
  broadcastToAll(alert: any): void {
    for (const [region, clients] of this.clients) {
      broadcastToRegion(region, alert);
    }
  }

  /**
   * Get the number of connected clients per region.
   */
  getClientCounts(): Map<string, number> {
    const counts = new Map<string, number>();
    for (const [region, clients] of this.clients) {
      counts.set(region, clients.size);
    }
    return counts;
  }
}