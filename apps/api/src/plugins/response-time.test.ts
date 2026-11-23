import { describe, it, expect, vi } from 'vitest';
import Fastify from 'fastify';
import { Readable } from 'stream';
import responseTimePlugin from './response-time';

describe('Response Time Plugin (Unit)', () => {
  it('attaches X-Response-Time header formatted to 2 decimal places', async () => {
    const app = Fastify();
    await app.register(responseTimePlugin);

    app.get('/test', async () => ({ ok: true }));

    const res = await app.inject({
      method: 'GET',
      url: '/test',
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers['x-response-time']).toBeDefined();
    expect(res.headers['x-response-time']).toMatch(/^\d+\.\d{2}ms$/);

    const match = (res.headers['x-response-time'] as string).match(/^(\d+\.\d{2})ms$/);
    expect(match).not.toBeNull();
    const duration = parseFloat(match![1]);
    expect(duration).toBeGreaterThanOrEqual(0);

    await app.close();
  });

  it('uses high-resolution monotonic timer (process.hrtime.bigint)', async () => {
    const app = Fastify();
    await app.register(responseTimePlugin);

    let recordedStartTime: bigint | undefined;
    app.get('/timer-check', async (request) => {
      recordedStartTime = request.startTime;
      return { ok: true };
    });

    const res = await app.inject({
      method: 'GET',
      url: '/timer-check',
    });

    expect(res.statusCode).toBe(200);
    expect(typeof recordedStartTime).toBe('bigint');
    expect(recordedStartTime).toBeGreaterThan(0n);
    expect(res.headers['x-response-time']).toMatch(/^\d+\.\d{2}ms$/);

    await app.close();
  });

  it('does not interfere with streaming responses', async () => {
    const app = Fastify();
    await app.register(responseTimePlugin);

    app.get('/stream', async (_request, reply) => {
      const stream = Readable.from(['chunk1', 'chunk2', 'chunk3']);
      return reply.type('text/plain').send(stream);
    });

    const res = await app.inject({
      method: 'GET',
      url: '/stream',
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toBe('chunk1chunk2chunk3');
    expect(res.headers['x-response-time']).toBeDefined();
    expect(res.headers['x-response-time']).toMatch(/^\d+\.\d{2}ms$/);

    await app.close();
  });

  it('does not interfere with error responses and attaches header', async () => {
    const app = Fastify();
    await app.register(responseTimePlugin);

    app.get('/error', async () => {
      const error: any = new Error('Custom failure');
      error.statusCode = 500;
      throw error;
    });

    const res = await app.inject({
      method: 'GET',
      url: '/error',
    });

    expect(res.statusCode).toBe(500);
    const body = JSON.parse(res.body);
    expect(body.message).toBe('Custom failure');
    expect(res.headers['x-response-time']).toBeDefined();
    expect(res.headers['x-response-time']).toMatch(/^\d+\.\d{2}ms$/);

    await app.close();
  });

  it('handles 404 not found responses gracefully with timing header', async () => {
    const app = Fastify();
    await app.register(responseTimePlugin);

    const res = await app.inject({
      method: 'GET',
      url: '/non-existent-route',
    });

    expect(res.statusCode).toBe(404);
    expect(res.headers['x-response-time']).toBeDefined();
    expect(res.headers['x-response-time']).toMatch(/^\d+\.\d{2}ms$/);

    await app.close();
  });

  it('falls back safely if request.startTime is somehow missing', async () => {
    const app = Fastify();
    await app.register(responseTimePlugin);

    // Intentionally clear startTime in a preHandler hook
    app.addHook('preHandler', async (request) => {
      delete request.startTime;
    });

    app.get('/no-start-time', async () => ({ status: 'ok' }));

    const res = await app.inject({
      method: 'GET',
      url: '/no-start-time',
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers['x-response-time']).toBeDefined();
    expect(res.headers['x-response-time']).toMatch(/^\d+\.\d{2}ms$/);

    await app.close();
  });

  it('does not throw if reply.raw.headersSent is true', async () => {
    const app = Fastify();
    await app.register(responseTimePlugin);

    app.get('/early-flush', async (_request, reply) => {
      // Manually send headers before onSend
      reply.raw.writeHead(200, { 'Content-Type': 'application/json' });
      reply.raw.end(JSON.stringify({ flushed: true }));
      return reply;
    });

    const res = await app.inject({
      method: 'GET',
      url: '/early-flush',
    });

    expect(res.statusCode).toBe(200);
    await app.close();
  });
});
