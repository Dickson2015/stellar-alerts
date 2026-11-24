import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Command } from 'commander';
import { registerTailCommand } from './tail.js';
import { ApiClient } from '../lib/api.js';

vi.mock('../lib/api.js', () => ({ ApiClient: vi.fn() }));
vi.mock('../lib/auth.js', () => ({
  resolveAuth: vi.fn(() => ({ apiUrl: 'http://localhost:3001', token: 'test-token' })),
}));

const mockOpenPaymentStream = vi.fn();
const mockOpenSorobanEventStream = vi.fn();
const mockGetWallets = vi.fn();

const wallet = {
  id: 'wallet-1',
  userId: 'user-1',
  publicKey: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  createdAt: new Date(0),
};

function payment(id: string, asset: string, amount = '10') {
  return {
    id,
    walletId: wallet.id,
    txHash: `tx-${id}`,
    fromAddress: wallet.publicKey,
    amount,
    asset,
    receivedAt: '2026-11-24T10:20:30.000Z',
  };
}

function liveStream<T>(records: T[], onDrained?: () => void) {
  return async (opts: { signal?: AbortSignal }) =>
    (async function* () {
      yield* records;
      onDrained?.();
      await new Promise((_, reject) => {
        const fail = () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
        if (opts.signal?.aborted) fail();
        else opts.signal?.addEventListener('abort', fail);
      });
    })();
}

describe('tail command', () => {
  let program: Command;

  beforeEach(() => {
    vi.clearAllMocks();
    mockGetWallets.mockResolvedValue([wallet]);
    mockOpenPaymentStream.mockResolvedValue((async function* () {})());
    mockOpenSorobanEventStream.mockResolvedValue((async function* () {})());
    vi.mocked(ApiClient).mockImplementation(() => ({
      getWallets: mockGetWallets,
      openPaymentStream: mockOpenPaymentStream,
      openSorobanEventStream: mockOpenSorobanEventStream,
    } as unknown as ApiClient));
    program = new Command();
    program.exitOverride();
    program.option('--api-url <url>');
    registerTailCommand(program);
    process.exitCode = undefined;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    process.exitCode = undefined;
  });

  it('registers the command with all documented filter flags', () => {
    const command = program.commands.find((candidate) => candidate.name() === 'tail');
    expect(command).toBeDefined();
    expect(command!.description()).toContain('Tail live payments');
    expect(command!.options.map((option) => option.long)).toEqual(
      expect.arrayContaining(['--wallet', '--contract', '--asset', '--min-amount', '--output', '--token'])
    );
    expect(command!.options.find((option) => option.long === '--output')?.defaultValue).toBe('pretty');
  });

  it('rejects an invalid output format or minimum amount before connecting', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    await program.parseAsync(['node', 'cli', 'tail', '--output', 'xml']);
    expect(process.exitCode).toBe(1);
    await program.parseAsync(['node', 'cli', 'tail', '--min-amount', '-5']);
    expect(process.exitCode).toBe(1);
    expect(mockOpenPaymentStream).not.toHaveBeenCalled();
    expect(error).toHaveBeenCalledTimes(2);
  });

  it('filters events client-side, emits NDJSON on stdout and a summary on SIGINT', async () => {
    const sigintBefore = process.listenerCount('SIGINT');
    const sigtermBefore = process.listenerCount('SIGTERM');
    const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    const records = [
      payment('p1', 'USDC', '10'),
      payment('p2', 'XLM', '1'),
      payment('p3', 'USDC', '50'),
    ];
    mockOpenPaymentStream.mockImplementation(liveStream(records, () => process.emit('SIGINT')));

    await program.parseAsync(['node', 'cli', 'tail', '--asset', 'USDC', '--min-amount', '20', '--output', 'ndjson']);

    const written = stdout.mock.calls.map((call) => String(call[0])).join('');
    const lines = written.trim().split('\n').filter(Boolean).map((line) => JSON.parse(line) as { id: string });
    expect(lines.map((line) => line.id)).toEqual(['p3']);
    expect(stderr.mock.calls.map((call) => String(call[0])).join('')).toContain('Events inspected: 3');
    expect(stderr.mock.calls.map((call) => String(call[0])).join('')).toContain('Matched:          1');
    expect(process.listenerCount('SIGINT')).toBe(sigintBefore);
    expect(process.listenerCount('SIGTERM')).toBe(sigtermBefore);
    expect(process.exitCode).toBeUndefined();
  });

  it('passes resolved wallet and server-side filters to the payment stream and opens Soroban events', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});

    mockOpenPaymentStream.mockImplementation(liveStream([payment('p1', 'USDC')], () => process.emit('SIGINT')));
    mockOpenSorobanEventStream.mockImplementation(
      liveStream([{ id: 's1', contractId: 'CCONTRACT', asset: 'USDC', amount: 5 }])
    );

    await program.parseAsync([
      'node', 'cli', 'tail',
      '--wallet', wallet.publicKey,
      '--contract', 'CCONTRACT',
      '--asset', 'USDC',
      '--min-amount', '4',
    ]);

    expect(mockOpenPaymentStream).toHaveBeenCalledWith(expect.objectContaining({
      walletId: wallet.id,
      asset: 'USDC',
      minAmount: 4,
      contract: 'CCONTRACT',
    }));
    expect(mockOpenSorobanEventStream).toHaveBeenCalledWith(expect.objectContaining({
      contract: 'CCONTRACT',
      asset: 'USDC',
    }));
  });
});
