import type { FastifyInstance } from 'fastify';
import { authenticateHook } from '../../middleware/auth.middleware';
import {
  TIME_SERIES_INTERVALS,
  timeSeriesRollupEngine,
  type TimeSeriesInterval,
} from './timeseries-rollup';

export async function analyticsRoutes(app: FastifyInstance) {
  app.addHook('preHandler', authenticateHook);

  app.get<{
    Querystring: { interval?: string; from?: string; to?: string; asset?: string; limit?: string };
  }>('/analytics/timeseries', async (request, reply) => {
    const { interval, from, to, asset, limit } = request.query;
    if (!interval || !(interval in TIME_SERIES_INTERVALS)) {
      return reply.code(400).send({ error: 'interval must be one of 1m, 5m, or 1h' });
    }

    const start = new Date(from ?? '');
    const end = new Date(to ?? '');
    if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || start >= end) {
      return reply.code(400).send({ error: 'from and to must be valid timestamps and from must precede to' });
    }

    const parsedLimit = limit === undefined ? undefined : Number(limit);
    if (parsedLimit !== undefined && (!Number.isInteger(parsedLimit) || parsedLimit < 1)) {
      return reply.code(400).send({ error: 'limit must be a positive integer' });
    }

    const buckets = await timeSeriesRollupEngine.query({
      interval: interval as TimeSeriesInterval,
      from: start,
      to: end,
      asset,
      limit: parsedLimit,
    });
    return { buckets };
  });
}
