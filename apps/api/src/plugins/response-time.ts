import fp from 'fastify-plugin';
import { FastifyInstance, FastifyPluginAsync } from 'fastify';

declare module 'fastify' {
  interface FastifyRequest {
    startTime?: bigint;
  }
}

/**
 * Fastify plugin that measures server-side request execution duration using
 * high-resolution monotonic timers (process.hrtime.bigint()) and attaches an
 * `X-Response-Time` HTTP response header formatted to 2 decimal places (e.g. `4.25ms`).
 */
const responseTimePluginAsync: FastifyPluginAsync = async (server: FastifyInstance) => {
  server.addHook('onRequest', async (request) => {
    request.startTime = process.hrtime.bigint();
  });

  server.addHook('onSend', async (request, reply, payload) => {
    const startTime = request.startTime ?? process.hrtime.bigint();
    const now = process.hrtime.bigint();
    const diffNs = now >= startTime ? now - startTime : 0n;
    const durationMs = (Number(diffNs) / 1_000_000).toFixed(2);

    if (!reply.raw.headersSent) {
      reply.header('X-Response-Time', `${durationMs}ms`);
    }

    return payload;
  });
};

export const responseTimePlugin = fp(responseTimePluginAsync, {
  name: 'response-time',
});

export default responseTimePlugin;
