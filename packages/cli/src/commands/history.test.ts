import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Command } from 'commander';
import { registerHistoryCommand } from './history.js';
import * as api from '../lib/api.js';
import * as auth from '../lib/auth.js';

vi.mock('../lib/api.js');
vi.mock('../lib/auth.js');

describe('history command', () => {
  let program: Command;
  let mockGetPayments: ReturnType<typeof vi.fn>;
  let consoleLogSpy: ReturnType<typeof vi.spyOn>;
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    program = new Command();
    program.option('-u, --api-url <url>', 'API base URL', 'http://localhost:3001');
    
    mockGetPayments = vi.fn();
    vi.mocked(api.ApiClient).mockImplementation(() => ({
      getPayments: mockGetPayments,
    } as any));

    vi.mocked(auth.resolveAuth).mockReturnValue({
      token: 'test-token',
      apiUrl: 'http://localhost:3001',
    });

    consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  it('should accept json format flag', async () => {
    registerHistoryCommand(program);
    const cmd = program.commands.find(c => c.name() === 'history');
    expect(cmd).toBeDefined();
    
    const formatOption = cmd?.options.find(opt => opt.flags.includes('--format'));
    expect(formatOption).toBeDefined();
    expect(formatOption?.description).toContain('json');
    expect(formatOption?.description).toContain('table');
  });

  it('should accept table format flag', async () => {
    registerHistoryCommand(program);
    const cmd = program.commands.find(c => c.name() === 'history');
    
    const formatOption = cmd?.options.find(opt => opt.flags.includes('--format'));
    expect(formatOption?.defaultValue).toBe('table');
  });

  it('should output valid JSON when format is json', async () => {
    const mockPayments = [
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
    mockGetPayments.mockResolvedValue(mockPayments);

    registerHistoryCommand(program);
    await program.parseAsync(['node', 'cli', 'history', '--format', 'json']);

    expect(consoleLogSpy).toHaveBeenCalled();
    const output = consoleLogSpy.mock.calls[0][0];
    expect(() => JSON.parse(output)).not.toThrow();
    expect(JSON.parse(output)).toEqual(mockPayments);
  });

  it('should exit with error code 1 for invalid format', async () => {
    const mockExit = vi.spyOn(process, 'exit').mockImplementation(() => undefined as never);
    
    registerHistoryCommand(program);
    await program.parseAsync(['node', 'cli', 'history', '--format', 'xml']);

    expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('Invalid format'));
    expect(mockExit).toHaveBeenCalledWith(1);
  });

  it('should use table format as default', async () => {
    mockGetPayments.mockResolvedValue([]);

    registerHistoryCommand(program);
    await program.parseAsync(['node', 'cli', 'history']);

    // Should show table output (empty message)
    expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('No payment history'));
  });
});
