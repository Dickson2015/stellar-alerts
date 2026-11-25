import type { FastifyReply, FastifyRequest } from 'fastify';
import { AuthenticationError, ValidationError } from '../../lib/errors';
import {
  BacktestReplayEngine,
  type BacktestPaymentSource,
  type CandidateRule,
} from './backtest-engine';
import { PrismaBacktestPaymentSource } from './backtest-source';

const MAX_RANGE_DAYS = 90;
const DAY_MS = 86_400_000;

interface BacktestBody {
  rule?: {
    walletId?: string | null;
    name?: string | null;
    assets?: string[];
    minAmount?: number | string | null;
    maxAmount?: number | string | null;
    memo?: string | null;
    conditions?: any;
  };
  startLedger?: number;
  endLedger?: number;
  from?: string;
  to?: string;
  sampleSize?: number;
}

export class RulesController {
  private readonly engine: BacktestReplayEngine;

  constructor(source: BacktestPaymentSource = new PrismaBacktestPaymentSource()) {
    this.engine = new BacktestReplayEngine(source);
  }

  /** POST /alert-rules/backtest. Dry-run only: nothing is persisted or dispatched. */
  async backtest(request: FastifyRequest, reply: FastifyReply) {
    if (!request.user) throw new AuthenticationError('User not authenticated');

    const body = (request.body ?? {}) as BacktestBody;
    if (!body.rule || typeof body.rule !== 'object') {
      throw new ValidationError('rule is required');
    }
    if (body.rule.assets !== undefined && !Array.isArray(body.rule.assets)) {
      throw new ValidationError('rule.assets must be an array');
    }

    const from = parseDate('from', body.from);
    const to = parseDate('to', body.to);
    if (from && to && (to.getTime() - from.getTime()) / DAY_MS > MAX_RANGE_DAYS) {
      throw new ValidationError(`Date range may not exceed ${MAX_RANGE_DAYS} days`);
    }

    const candidate: CandidateRule = {
      walletId: body.rule.walletId ?? null,
      name: body.rule.name ?? null,
      assets: body.rule.assets ?? [],
      minAmount: body.rule.minAmount ?? null,
      maxAmount: body.rule.maxAmount ?? null,
      memo: body.rule.memo ?? null,
      conditions: body.rule.conditions ?? null,
    };

    const report = await this.engine.run(
      candidate,
      { startLedger: body.startLedger, endLedger: body.endLedger, from, to },
      { userId: request.user.id, walletId: candidate.walletId },
      { sampleSize: body.sampleSize },
    );

    return reply.send({ success: true, report });
  }
}

function parseDate(name: string, value: unknown): Date | undefined {
  if (value === undefined || value === null) return undefined;
  const d = new Date(String(value));
  if (Number.isNaN(d.getTime())) throw new ValidationError(`${name} must be a valid ISO date`);
  return d;
}

export const rulesController = new RulesController();
