import { Command } from 'commander';
import chalk from 'chalk';
import { ApiClient } from '../lib/api.js';
import { resolveAuth } from '../lib/auth.js';
import { formatPaymentsAsTable, formatPaymentsAsJson } from '../utils/formatters.js';

export function registerHistoryCommand(program: Command): void {
  program
    .command('history')
    .description('View alert history')
    .option('-w, --wallet-id <walletId>', 'Filter by wallet ID')
    .option('-l, --limit <limit>', 'Limit number of results', '50')
    .option('-f, --format <format>', 'Output format: json or table (default: table)', 'table')
    .option('-t, --token <token>', 'API authentication token (overrides profile)')
    .action(async (options: { walletId?: string; limit?: string; format?: string; token?: string }) => {
      try {
        const auth = resolveAuth(options.token, program.opts().apiUrl);
        const client = new ApiClient(auth.apiUrl, auth.token);

        // Validate format option
        const format = options.format?.toLowerCase();
        if (format !== 'json' && format !== 'table') {
          console.error(chalk.red(`❌ Error: Invalid format option '${options.format}'`));
          console.error(chalk.yellow('Valid options are: json, table'));
          console.error(chalk.gray('Usage: stellar-alerts history --format <json|table>'));
          process.exit(1);
        }

        const limit = parseInt(options.limit || '50', 10);
        if (isNaN(limit) || limit <= 0) {
          console.error(chalk.red(`❌ Error: Invalid limit value '${options.limit}'`));
          process.exit(1);
        }

        const payments = await client.getPayments(options.walletId, limit);

        if (format === 'json') {
          formatPaymentsAsJson(payments);
        } else {
          formatPaymentsAsTable(payments);
        }
      } catch (error) {
        console.error(chalk.red(`❌ Error: ${(error as Error).message}`));
        process.exit(1);
      }
    });
}
