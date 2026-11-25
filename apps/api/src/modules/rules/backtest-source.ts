import { prisma } from '../../lib/prisma';
import { multiNodeClient } from '../../lib/stellar';
import { ValidationError } from '../../lib/errors';
import type {
  BacktestPaymentSource,
  BacktestRange,
  BacktestScope,
  HistoricalPayment,
} from './backtest-engine';

const PAGE_SIZE = 1000;

/** Resolves a ledger sequence to its close time (UTC). */
export type LedgerCloseTimeResolver = (sequence: number) => Promise<Date>;

/** Default resolver: asks Horizon for the ledger's `closed_at`. Read-only. */
export const horizonLedgerCloseTime: LedgerCloseTimeResolver = async (sequence) => {
  const server = multiNodeClient.servers[0];
  if (!server) throw new ValidationError('No Horizon endpoint configured for ledger lookup');
  try {
    const ledger = (await server.ledgers().ledger(sequence).call()) as unknown as { closed_at: string };
    return new Date(ledger.closed_at);
  } catch {
    throw new ValidationError(`Ledger ${sequence} could not be resolved`, { sequence }, 'LEDGER_NOT_FOUND');
  }
};

/**
 * Read-only, Postgres-backed history. Payments are not stored with a ledger
 * sequence, so a ledger range is translated to the close times of its
 * boundary ledgers and intersected with any explicit date range.
 * Rows are keyset-paginated by (receivedAt, id) so ordering, and therefore the
 * replay, is deterministic.
 */
export class PrismaBacktestPaymentSource implements BacktestPaymentSource {
  constructor(private readonly resolveLedger: LedgerCloseTimeResolver = horizonLedgerCloseTime) {}

  async *stream(range: BacktestRange, scope: BacktestScope): AsyncIterable<HistoricalPayment> {
    const { from, to } = await this.resolveWindow(range);

    let cursor: { receivedAt: Date; id: string } | null = null;
    for (;;) {
      const rows: any[] = await (prisma as any).payment.findMany({
        where: {
          wallet: { userId: scope.userId, deletedAt: null },
          ...(scope.walletId ? { walletId: scope.walletId } : {}),
          receivedAt: { ...(from ? { gte: from } : {}), ...(to ? { lte: to } : {}) },
          ...(cursor
            ? {
                OR: [
                  { receivedAt: { gt: cursor.receivedAt } },
                  { receivedAt: cursor.receivedAt, id: { gt: cursor.id } },
                ],
              }
            : {}),
        },
        orderBy: [{ receivedAt: 'asc' }, { id: 'asc' }],
        take: PAGE_SIZE,
      });

      for (const row of rows) {
        yield {
          paymentId: row.id,
          txHash: row.txHash,
          walletId: row.walletId,
          userId: scope.userId,
          amount: row.amount.toString(),
          asset: row.asset,
          assetIssuer: row.assetIssuer,
          fromAddress: row.fromAddress,
          memo: row.memo,
          receivedAt: row.receivedAt.toISOString(),
        };
      }

      if (rows.length < PAGE_SIZE) return;
      const last = rows[rows.length - 1];
      cursor = { receivedAt: last.receivedAt, id: last.id };
    }
  }

  private async resolveWindow(range: BacktestRange): Promise<{ from?: Date; to?: Date }> {
    let from = range.from;
    let to = range.to;

    if (range.startLedger !== undefined) {
      const t = await this.resolveLedger(range.startLedger);
      from = from && from > t ? from : t;
    }
    if (range.endLedger !== undefined) {
      const t = await this.resolveLedger(range.endLedger);
      to = to && to < t ? to : t;
    }
    return { from, to };
  }
}
