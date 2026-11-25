import chalk from 'chalk';
import { PaymentDTO } from '../lib/types.js';

/**
 * Outputs payments as a formatted ANSI table to stdout
 */
export function formatPaymentsAsTable(payments: PaymentDTO[]): void {
  if (payments.length === 0) {
    console.log(chalk.yellow('📭 No payment history found.'));
    return;
  }

  console.log(chalk.blue(`\n📜 Payment History (${payments.length} records)\n`));
  console.log(chalk.gray('─'.repeat(120)));
  console.log(
    chalk.bold(
      'ID'.padEnd(28) +
      'From'.padEnd(58) +
      'Amount'.padEnd(18) +
      'Asset'.padEnd(10) +
      'Date'
    )
  );
  console.log(chalk.gray('─'.repeat(120)));

  for (const payment of payments) {
    const amount = typeof payment.amount === 'string' ? payment.amount : payment.amount.toString();
    const date = new Date(payment.receivedAt).toLocaleString();
    const fromAddr = payment.fromAddress.length > 56 
      ? payment.fromAddress.substring(0, 53) + '...' 
      : payment.fromAddress;

    console.log(
      `${chalk.cyan(payment.id.substring(0, 26).padEnd(28))}` +
      `${fromAddr.padEnd(58)}` +
      `${chalk.green(amount.padEnd(18))}` +
      `${payment.asset.padEnd(10)}` +
      `${chalk.gray(date)}`
    );
  }

  console.log(chalk.gray('─'.repeat(120)));
  console.log('');
}

/**
 * Outputs payments as valid JSON array to stdout
 */
export function formatPaymentsAsJson(payments: PaymentDTO[]): void {
  console.log(JSON.stringify(payments, null, 2));
}
