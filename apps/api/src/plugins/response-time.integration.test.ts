import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';

// Mock env
vi.mock('../config/env', () => ({
  env: {
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    TELEGRAM_BOT_TOKEN: 'test-token',
    JWT_SECRET: 'test-super-secret-jwt-key-for-testing-only',
    REDIS_URL: 'redis://localhost:6379',
    PORT: '3001',
    APP_URL: 'http://localhost:3000',
    CSRF_ALLOWED_ORIGINS: 'http://localhost:3000',
    RATE_LIMIT_MAX: 100,
    WASM_ANALYZER_MAX_UPLOAD_BYTES: 5242880,
  },
}));

vi.mock('../lib/prisma', () => ({
  prisma: {
    $connect: vi.fn().mockResolvedValue(undefined),
    $disconnect: vi.fn().mockResolvedValue(undefined),
    $queryRaw: vi.fn().mockResolvedValue([{ '?column?': 1 }]),
  },
  prismaRead: {
    $connect: vi.fn().mockResolvedValue(undefined),
    $queryRaw: vi.fn().mockResolvedValue([{ '?column?': 1 }]),
  },
}));

vi.mock('../plugins/prisma', () => ({
  default: async () => {},
}));

vi.mock('../plugins/websocket', () => ({
  registerSSEPushPlugin: async () => {},
}));

vi.mock('../plugins/metrics', () => ({
  default: async () => {},
}));

vi.mock('../plugins/degraded-mode', () => ({
  default: async () => {},
}));

vi.mock('../lib/queue', () => ({
  alertQueue: null,
}));

vi.mock('../lib/soroban', () => ({
  sorobanServer: {},
}));

vi.mock('../lib/redis', () => ({
  checkRedisReadiness: vi.fn().mockResolvedValue(true),
  getRedisStatus: vi.fn().mockReturnValue({ connected: true }),
}));

// Stub out route modules so buildApp doesn't load unrelated controllers
vi.mock('../modules/auth/auth.routes', () => ({ authRoutes: async () => {} }));
vi.mock('../modules/wallets/wallets.routes', () => ({ walletsRoutes: async () => {} }));
vi.mock('../modules/payments/payments.routes', () => ({ paymentsRoutes: async () => {} }));
vi.mock('../modules/webhooks/webhooks.routes', () => ({ webhooksRoutes: async () => {} }));
vi.mock('../modules/account/account.routes', () => ({ accountRoutes: async () => {} }));
vi.mock('../modules/notifications/notifications.routes', () => ({ notificationsRoutes: async () => {} }));
vi.mock('../modules/alert-rules/alert-rules.routes', () => ({ alertRulesRoutes: async () => {} }));
vi.mock('../modules/dead-letters/dead-letters.routes', () => ({ deadLettersRoutes: async () => {} }));
vi.mock('../modules/slack/slack.routes', () => ({ slackRoutes: async () => {} }));
vi.mock('../modules/graphql/graphql.routes', () => ({ graphqlRoutes: async () => {} }));
vi.mock('../modules/exports/exports.routes', () => ({ exportsRoutes: async () => {} }));
vi.mock('../modules/simulation/simulation.routes', () => ({ simulationRoutes: async () => {} }));
vi.mock('../modules/discord-interactions', () => ({ discordInteractionsRoutes: async () => {} }));
vi.mock('../modules/admin/admin.routes', () => ({ adminRoutes: async () => {} }));
vi.mock('../modules/soroban-state/soroban-state.routes', () => ({ sorobanStateRoutes: async () => {} }));
vi.mock('../modules/wasm-analyzer/wasm-analyzer.routes', () => ({ wasmAnalyzerRoutes: async () => {} }));
vi.mock('../modules/audit/audit.routes', () => ({ auditRoutes: async () => {} }));
vi.mock('../modules/slack-interactions', () => ({ slackInteractionsRoutes: async () => {} }));

import { buildApp } from '../app';

describe('X-Response-Time Header Hook Integration (#959)', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp();
  }, 15000);

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  describe('GET /health', () => {
    it('returns 200 with X-Response-Time header formatted to 2 decimal places', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/health',
      });

      expect(res.statusCode).toBe(200);
      expect(JSON.parse(res.body)).toEqual({ status: 'ok' });

      // Assert presence and exact format: <ms>ms formatted to 2 decimal places
      const responseTimeHeader = res.headers['x-response-time'];
      expect(responseTimeHeader).toBeDefined();
      expect(typeof responseTimeHeader).toBe('string');
      expect(responseTimeHeader).toMatch(/^\d+\.\d{2}ms$/);

      const parsedMs = parseFloat((responseTimeHeader as string).replace('ms', ''));
      expect(parsedMs).toBeGreaterThanOrEqual(0);
    });

    it('consistently attaches X-Response-Time header across multiple consecutive requests', async () => {
      for (let i = 0; i < 5; i++) {
        const res = await app.inject({
          method: 'GET',
          url: '/health',
        });

        expect(res.statusCode).toBe(200);
        expect(res.headers['x-response-time']).toBeDefined();
        expect(res.headers['x-response-time']).toMatch(/^\d+\.\d{2}ms$/);
      }
    });
  });

  describe('Error and 404 responses', () => {
    it('attaches X-Response-Time header to 404 responses without altering error payload', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/unknown-endpoint-for-testing',
      });

      expect(res.statusCode).toBe(404);
      expect(res.headers['x-response-time']).toBeDefined();
      expect(res.headers['x-response-time']).toMatch(/^\d+\.\d{2}ms$/);
    });
  });
});
