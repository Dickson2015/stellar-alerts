import { Command } from 'commander';
import chalk from 'chalk';
import { ApiClient } from '../lib/api.js';
import type { PaymentDTO, SorobanEventDTO } from '../lib/types.js';
import { resolveAuth } from '../lib/auth.js';
import {
  type TailEvent,
  type TailFilter,
  matchesTailFilter,
  paymentToTailEvent,
  sorobanEventToTailEvent,
  serializeNdjson,
  formatHumanEvent,
  formatSessionSummary,
} from '../utils/stream-printer.js';

interface TailOptions {
  wallet?: string;
  contract?: string;
  asset?: string;
  minAmount?: string;
  output?: string;
  token?: string;
}

interface MutableStats {
  inspected: number;
  matched: number;
}

async function consumeStream<T>(
  stream: AsyncIterable<T>,
  convert: (raw: T) => TailEvent,
  filter: TailFilter,
  onEvent: (event: TailEvent) => void,
  stats: MutableStats,
  signal: AbortSignal
): Promise<void> {
  try {
    for await (const raw of stream) {
      if (signal.aborted) break;
      stats.inspected += 1;
      const event = convert(raw);
      if (!matchesTailFilter(event, filter)) continue;
      stats.matched += 1;
      onEvent(event);
    }
  } catch (error) {
    // Aborting the fetch closes the reader with an AbortError; that is a clean stop.
    if (signal.aborted || (error instanceof Error && error.name === 'AbortError')) return;
    throw error;
  }
}

/**
 * Registers the `tail` command: an ephemeral, filterable live stream of payment
 * and Soroban events. Filters are sent to the server when supported and always
 * re-applied client-side, so the command works against older servers too.
 */
export function registerTailCommand(program: Command): void {
  program
    .command('tail')
    .description('Tail live payments and Soroban events with ephemeral filters')
    .option('-w, --wallet <address>', 'Filter by wallet address or wallet id')
    .option('-c, --contract <id>', 'Filter by Soroban contract id')
    .option('-a, --asset <code>', 'Filter by asset code')
    .option('-m, --min-amount <number>', 'Only show events at or above this amount')
    .option('-o, --output <format>', 'Output format: pretty or ndjson', 'pretty')
    .option('-t, --token <token>', 'API authentication token (overrides profile)')
    .action(async (options: TailOptions) => {
      const format = (options.output ?? 'pretty').toLowerCase();
      if (format !== 'pretty' && format !== 'ndjson') {
        console.error(chalk.red(`❌ --output must be "pretty" or "ndjson", got "${options.output}"`));
        process.exitCode = 1;
        return;
      }

      let minAmount: number | undefined;
      if (options.minAmount !== undefined) {
        minAmount = Number(options.minAmount);
        if (!Number.isFinite(minAmount) || minAmount < 0) {
          console.error(chalk.red(`❌ --min-amount must be a non-negative number, got "${options.minAmount}"`));
          process.exitCode = 1;
          return;
        }
      }

      const filter: TailFilter = {
        wallet: options.wallet,
        contract: options.contract,
        asset: options.asset,
        minAmount,
      };

      const abortController = new AbortController();
      const onSigInt = () => {
        if (abortController.signal.aborted) process.exit(130);
        abortController.abort();
      };
      const onSigTerm = () => {
        if (abortController.signal.aborted) process.exit(130);
        abortController.abort();
      };
      process.on('SIGINT', onSigInt);
      process.on('SIGTERM', onSigTerm);

      const startedAt = Date.now();
      const stats: MutableStats = { inspected: 0, matched: 0 };
      const onEvent = (event: TailEvent) => {
        if (format === 'ndjson') {
          process.stdout.write(`${serializeNdjson(event)}\n`);
        } else {
          console.log(formatHumanEvent(event, filter));
        }
      };

      try {
        const auth = resolveAuth(options.token, program.opts().apiUrl);
        const client = new ApiClient(auth.apiUrl, auth.token);

        // Resolve an address to a wallet id so servers that support filtering can
        // narrow the stream before it reaches the client.
        let walletId: string | undefined;
        if (options.wallet) {
          const wallets = await client.getWallets();
          const target = options.wallet;
          const match = wallets.find((wallet) =>
            wallet.id === target || wallet.publicKey.toLowerCase() === target.toLowerCase()
          );
          if (match) {
            walletId = match.id;
          } else if (format === 'pretty') {
            console.warn(chalk.yellow(`⚠  Wallet "${target}" is not registered; filtering client-side only.`));
          }
        }

        if (format === 'pretty') {
          console.log(chalk.bold.blue('\n🌊 Live tail'));
          console.log(chalk.gray(`Filters: ${JSON.stringify(filter)}`));
          console.log(chalk.gray('Press Ctrl+C for session statistics.\n'));
        }

        const payments = await client.openPaymentStream({
          walletId,
          asset: options.asset,
          minAmount,
          contract: options.contract,
          signal: abortController.signal,
        });
        const streams: Array<Promise<void>> = [
          consumeStream(payments, paymentToTailEvent, filter, onEvent, stats, abortController.signal),
        ];

        // Only connect to the Soroban stream when a Soroban-oriented filter is
        // present: servers without that endpoint can still serve payment tails.
        if (options.contract || options.asset) {
          try {
            const events = await client.openSorobanEventStream({
              contract: options.contract,
              asset: options.asset,
              signal: abortController.signal,
            });
            streams.push(
              consumeStream(events, sorobanEventToTailEvent, filter, onEvent, stats, abortController.signal)
            );
          } catch (error) {
            if (format === 'pretty') {
              console.warn(chalk.yellow(`⚠  Soroban event stream unavailable: ${(error as Error).message}`));
            }
          }
        }

        await Promise.all(streams);
      } catch (error) {
        if (!abortController.signal.aborted) {
          console.error(chalk.red(`\n❌ Error: ${(error as Error).message}`));
          process.exitCode = 1;
        }
      } finally {
        process.off('SIGINT', onSigInt);
        process.off('SIGTERM', onSigTerm);
        const summary = formatSessionSummary({
          startedAt,
          endedAt: Date.now(),
          inspected: stats.inspected,
          matched: stats.matched,
        });
        // Keep stdout pipe-clean in NDJSON mode.
        if (format === 'ndjson') console.error(summary);
        else console.log(summary);
      }
    });
}
