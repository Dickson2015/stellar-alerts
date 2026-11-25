import { describe, it, expect, vi, beforeEach } from 'vitest';
import { formatPaymentsAsJson, formatPaymentsAsTable } from './formatters.js';
import { PaymentDTO } from '../lib/types.js';

describe('formatters', () => {
  let consoleLogSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  describe('formatPaymentsAsJson', () => {
    it('should output valid JSON array', () => {
      const payments: PaymentDTO[] = [
        {
          id: 'payment-1',
          walletId: 'wallet-1',
          txHash: 'hash-1',
          fromAddress: 'GABC123',
          amount: '100.00',
          asset: 'XLM',
          receivedAt: '2024-01-01T00:00:00Z',
        },
      ];

      formatPaymentsAsJson(payments);

      expect(consoleLogSpy).toHaveBeenCalled();
      const output = consoleLogSpy.mock.calls[0][0];
      expect(() => JSON.parse(output)).not.toThrow();
      expect(JSON.parse(output)).toEqual(payments);
    });

    it('should output empty array for no payments', () => {
      formatPaymentsAsJson([]);

      expect(consoleLogSpy).toHaveBeenCalledWith('[]');
    });

    it('should preserve all payment properties in JSON output', () => {
      const payments: PaymentDTO[] = [
        {
          id: 'payment-1',
          walletId: 'wallet-1',
          txHash: 'hash-1',
          fromAddress: 'GABC123',
          amount: 100.5,
          asset: 'XLM',
          memo: 'Test memo',
          receivedAt: '2024-01-01T00:00:00Z',
          pagingToken: 'token-1',
        },
      ];

      formatPaymentsAsJson(payments);

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output[0]).toHaveProperty('memo', 'Test memo');
      expect(output[0]).toHaveProperty('pagingToken', 'token-1');
    });
  });

  describe('formatPaymentsAsTable', () => {
    it('should output formatted table for payments', () => {
      const payments: PaymentDTO[] = [
        {
          id: 'payment-1',
          walletId: 'wallet-1',
          txHash: 'hash-1',
          fromAddress: 'GABC123',
          amount: '100.00',
          asset: 'XLM',
          receivedAt: '2024-01-01T00:00:00Z',
        },
      ];

      formatPaymentsAsTable(payments);

      expect(consoleLogSpy).toHaveBeenCalled();
      const calls = consoleLogSpy.mock.calls.map(c => c[0]);
      const output = calls.join('\n');
      
      expect(output).toContain('Payment History');
      expect(output).toContain('payment-1');
      expect(output).toContain('GABC123');
      expect(output).toContain('100.00');
      expect(output).toContain('XLM');
    });

    it('should show message when no payments exist', () => {
      formatPaymentsAsTable([]);

      expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('No payment history found'));
    });

    it('should handle numeric amount values', () => {
      const payments: PaymentDTO[] = [
        {
          id: 'payment-1',
          walletId: 'wallet-1',
          txHash: 'hash-1',
          fromAddress: 'GABC123',
          amount: 100,
          asset: 'XLM',
          receivedAt: '2024-01-01T00:00:00Z',
        },
      ];

      formatPaymentsAsTable(payments);

      const calls = consoleLogSpy.mock.calls.map(c => c[0]);
      const output = calls.join('\n');
      expect(output).toContain('100');
    });
  });
});
