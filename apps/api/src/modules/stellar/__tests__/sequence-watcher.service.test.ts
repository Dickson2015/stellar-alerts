import * as StellarSdk from 'stellar-sdk';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { redisStore, stellarMock } = vi.hoisted(() => ({
  redisStore: new Map<string, string>(),
  stellarMock: {
    getLatestOperationPagingToken: vi.fn(),
    getAccountOperationsSince: vi.fn(),
    isTransactionOnLedger: vi.fn(),
  },
}));

vi.mock('../../../lib/prisma', () => ({ prisma: {} }));
vi.mock('../../../lib/stellar', () => ({ stellar: stellarMock }));
vi.mock('../../../lib/queue', () => ({ dispatchWebhookAndLog: vi.fn() }));
vi.mock('../../../lib/redis', () => ({
  redisCache: {
    get: async (key: string) => redisStore.get(key) ?? null,
    set: async (key: string, value: string) => {
      redisStore.set(key, value);
    },
    del: async (key: string) => (redisStore.delete(key) ? 1 : 0),
    setNx: async (key: string, value: string) => {
      if (redisStore.has(key)) return false;
      redisStore.set(key, value);
      return true;
    },
  },
}));

import {
  SequencePreconditionWatcher,
  buildSequenceTelegramMessage,
  calculateSequenceDelta,
  decodeEnvelope,
  detectSequenceEvent,
  findInvalidatedProposals,
  type PendingProposal,
  type SequenceOperation,
  type SequenceWatcherDeps,
} from '../sequence-watcher.service';

const NETWORK = StellarSdk.Networks.TESTNET;
const treasuryKey = StellarSdk.Keypair.fromRawEd25519Seed(Buffer.alloc(32, 1));
const otherKey = StellarSdk.Keypair.fromRawEd25519Seed(Buffer.alloc(32, 2));
const signerKey = StellarSdk.Keypair.fromRawEd25519Seed(Buffer.alloc(32, 3));
const TREASURY = treasuryKey.publicKey();
const OTHER = otherKey.publicKey();

type BuilderOptions = ConstructorParameters<typeof StellarSdk.TransactionBuilder>[1];

/** Builds a transaction whose sequence number is exactly `sequence`. */
function buildTx(
  sequence: string,
  options: Partial<BuilderOptions> = {},
  source: StellarSdk.Keypair = treasuryKey,
  operation: StellarSdk.xdr.Operation = StellarSdk.Operation.bumpSequence({ bumpTo: '0' }),
): StellarSdk.Transaction {
  const account = new StellarSdk.Account(source.publicKey(), (BigInt(sequence) - 1n).toString());
  const builder = new StellarSdk.TransactionBuilder(account, {
    fee: '100',
    networkPassphrase: NETWORK,
    ...options,
  }).addOperation(operation);
  if (!options.timebounds) builder.setTimeout(StellarSdk.TimeoutInfinite);
  const tx = builder.build();
  tx.sign(source);
  return tx;
}

const xdrOf = (tx: StellarSdk.Transaction) => tx.toEnvelope().toXDR('base64');

function proposal(id: string, sequence: string, source: StellarSdk.Keypair = treasuryKey): PendingProposal {
  const tx = buildTx(sequence, {}, source);
  return { id, innerTxHash: tx.hash().toString('hex'), envelopeXdr: xdrOf(tx) };
}

function bumpOp(bumpTo: string, txSequence: string, overrides: Partial<SequenceOperation> = {}): SequenceOperation {
  const tx = buildTx(txSequence, {}, treasuryKey, StellarSdk.Operation.bumpSequence({ bumpTo }));
  return {
    id: 'op-1',
    paging_token: '200',
    type: 'bump_sequence',
    created_at: '2026-11-23T10:00:00Z',
    transaction_hash: tx.hash().toString('hex'),
    source_account: TREASURY,
    bump_to: bumpTo,
    transaction_attr: {
      hash: tx.hash().toString('hex'),
      source_account: TREASURY,
      source_account_sequence: txSequence,
      envelope_xdr: xdrOf(tx),
    },
    ...overrides,
  };
}

describe('decodeEnvelope', () => {
  it('decodes a transaction without V2 preconditions', () => {
    const decoded = decodeEnvelope(xdrOf(buildTx('101')));
    expect(decoded).toMatchObject({ sourceAccount: TREASURY, sequence: '101' });
    expect(decoded.preconditions).toMatchObject({ version: 'time', minSeqNum: null, ledgerBounds: null });
  });

  it('decodes every CAP-0021 PreconditionsV2 field', () => {
    const extra = StellarSdk.SignerKey.encodeSignerKey(
      StellarSdk.SignerKey.decodeAddress(signerKey.publicKey()),
    );
    const tx = buildTx('500', {
      timebounds: { minTime: 10, maxTime: 2_000_000_000 },
      ledgerbounds: { minLedger: 7, maxLedger: 900 },
      minAccountSequence: '450',
      minAccountSequenceAge: StellarSdk.xdr.Uint64.fromString('3600') as never,
      minAccountSequenceLedgerGap: 12,
      extraSigners: [extra],
    });

    expect(decodeEnvelope(xdrOf(tx))).toEqual({
      sourceAccount: TREASURY,
      sequence: '500',
      preconditions: {
        version: 'v2',
        timeBounds: { minTime: '10', maxTime: '2000000000' },
        ledgerBounds: { minLedger: 7, maxLedger: 900 },
        minSeqNum: '450',
        minSeqAge: '3600',
        minSeqLedgerGap: 12,
        extraSigners: [extra],
      },
    });
  });

  it('reads the inner transaction of a fee-bump envelope', () => {
    const inner = buildTx('777', { minAccountSequence: '700' });
    const feeBump = StellarSdk.TransactionBuilder.buildFeeBumpTransaction(otherKey, '200', inner, NETWORK);
    const decoded = decodeEnvelope(feeBump.toEnvelope().toXDR('base64'));
    expect(decoded).toMatchObject({ sourceAccount: TREASURY, sequence: '777' });
    expect(decoded.preconditions.minSeqNum).toBe('700');
  });

  it('throws on malformed XDR', () => {
    expect(() => decodeEnvelope('not-xdr')).toThrow();
  });
});

describe('calculateSequenceDelta', () => {
  it('calculates the exact delta beyond the safe-integer range', () => {
    expect(calculateSequenceDelta('9007199254740993', '9223372036854775807')).toEqual({
      previousSeq: '9007199254740993',
      bumpTo: '9223372036854775807',
      delta: '9214364837600034814',
      effective: true,
      watermark: '9223372036854775807',
    });
  });

  it('treats a bump at or below the current sequence as a no-op', () => {
    expect(calculateSequenceDelta('100', '100')).toMatchObject({ effective: false, delta: '0', watermark: '100' });
    expect(calculateSequenceDelta('100', '90')).toMatchObject({ effective: false, delta: '-10', watermark: '100' });
  });

  it('reports an unknown delta when the prior sequence is unknown', () => {
    expect(calculateSequenceDelta(null, '100')).toMatchObject({ delta: null, effective: true, watermark: '100' });
  });
});

describe('findInvalidatedProposals', () => {
  it('flags proposals at or below the water-mark and keeps those above it', () => {
    const flagged = findInvalidatedProposals(TREASURY, '200', [
      proposal('below', '150'),
      proposal('equal', '200'),
      proposal('next', '201'),
      proposal('future', '300'),
    ]);
    expect(flagged.map((item) => item.id)).toEqual(['below', 'equal']);
    expect(flagged[0]?.sequence).toBe('150');
  });

  it('ignores proposals sourced from another account', () => {
    expect(findInvalidatedProposals(TREASURY, '200', [proposal('foreign', '150', otherKey)])).toEqual([]);
  });

  it('skips and reports undecodable envelopes', () => {
    const onError = vi.fn();
    const bad = { id: 'bad', innerTxHash: 'x', envelopeXdr: 'garbage' };
    expect(findInvalidatedProposals(TREASURY, '200', [bad, proposal('ok', '100')], onError).map((p) => p.id)).toEqual(['ok']);
    expect(onError).toHaveBeenCalledWith(bad, expect.anything());
  });
});

describe('detectSequenceEvent', () => {
  it('calculates bumpTo minus the prior sequence', () => {
    const event = detectSequenceEvent(bumpOp('1000', '100'), TREASURY);
    expect(event).toMatchObject({ eventType: 'BUMP_SEQUENCE' });
    expect(event?.sequence).toMatchObject({ previousSeq: '100', delta: '900', watermark: '1000' });
  });

  it('ignores a no-op bump, a failed transaction and another account', () => {
    expect(detectSequenceEvent(bumpOp('50', '100'), TREASURY)).toBeNull();
    expect(detectSequenceEvent(bumpOp('1000', '100', { transaction_successful: false }), TREASURY)).toBeNull();
    expect(detectSequenceEvent(bumpOp('1000', '100', { source_account: OTHER }), TREASURY)).toBeNull();
  });

  it('does not claim an exact delta when another account submitted the transaction', () => {
    const tx = buildTx('100', {}, otherKey);
    const op = bumpOp('1000', '100', {
      transaction_attr: {
        hash: tx.hash().toString('hex'),
        source_account: OTHER,
        source_account_sequence: '100',
        envelope_xdr: xdrOf(tx),
      },
    });
    expect(detectSequenceEvent(op, TREASURY)?.sequence).toMatchObject({ previousSeq: null, delta: null, watermark: '1000' });
  });

  it('detects a minSeqNum transaction that skips sequence numbers', () => {
    const tx = buildTx('500', { minAccountSequence: '100' }, treasuryKey, StellarSdk.Operation.manageData({ name: 'k', value: 'v' }));
    const event = detectSequenceEvent(
      {
        id: 'op-9',
        type: 'manage_data',
        source_account: TREASURY,
        transaction_attr: { hash: tx.hash().toString('hex'), source_account: TREASURY, envelope_xdr: xdrOf(tx) },
      },
      TREASURY,
    );
    expect(event).toMatchObject({ eventType: 'MIN_SEQ_NUM_JUMP' });
    expect(event?.sequence).toMatchObject({ delta: '400', watermark: '500' });
  });

  it('does not flag a minSeqNum transaction that skips nothing', () => {
    const tx = buildTx('101', { minAccountSequence: '100' }, treasuryKey, StellarSdk.Operation.manageData({ name: 'k', value: 'v' }));
    expect(
      detectSequenceEvent(
        { id: 'op-9', type: 'manage_data', source_account: TREASURY, transaction_attr: { envelope_xdr: xdrOf(tx) } },
        TREASURY,
      ),
    ).toBeNull();
  });
});

describe('SequencePreconditionWatcher', () => {
  let deps: { [K in keyof SequenceWatcherDeps]: ReturnType<typeof vi.fn> };
  let watcher: SequencePreconditionWatcher;

  beforeEach(() => {
    redisStore.clear();
    vi.clearAllMocks();
    deps = {
      loadTreasury: vi.fn().mockResolvedValue({
        proposals: [proposal('dead-1', '150'), proposal('dead-2', '900'), proposal('live', '1001')],
        signerUserIds: ['signer-a', 'owner'],
      }),
      loadWalletUserIds: vi.fn().mockResolvedValue(['owner']),
      isOnLedger: vi.fn().mockResolvedValue(false),
      markExpired: vi.fn().mockResolvedValue(undefined),
      notify: vi.fn().mockResolvedValue(undefined),
    };
    watcher = new SequencePreconditionWatcher(deps as unknown as SequenceWatcherDeps);
  });

  it('alerts each signer once and expires the invalidated proposals', async () => {
    const alert = await watcher.processOperation(bumpOp('1000', '100'), TREASURY);

    expect(alert).toMatchObject({ severity: 'CRITICAL', delta: '900', newSeq: '1000' });
    expect(alert?.invalidatedProposals.map((item) => item.id)).toEqual(['dead-1', 'dead-2']);
    expect(deps.notify).toHaveBeenCalledWith(['owner', 'signer-a'], expect.anything());
    expect(deps.markExpired).toHaveBeenCalledWith(['dead-1', 'dead-2']);
  });

  it('does not report a proposal that actually executed', async () => {
    deps.isOnLedger.mockImplementation(async (hash: string) => {
      const treasury = await deps.loadTreasury.mock.results[0]?.value;
      return hash === treasury.proposals[0].innerTxHash;
    });
    const alert = await watcher.processOperation(bumpOp('1000', '100'), TREASURY);
    expect(alert?.invalidatedProposals.map((item) => item.id)).toEqual(['dead-2']);
    expect(deps.markExpired).toHaveBeenCalledWith(['dead-2']);
  });

  it('does not treat the bumping transaction as its own victim', async () => {
    const op = bumpOp('1000', '100');
    deps.loadTreasury.mockResolvedValue({
      proposals: [{ id: 'self', innerTxHash: op.transaction_attr?.hash, envelopeXdr: op.transaction_attr?.envelope_xdr }],
      signerUserIds: [],
    });
    const alert = await watcher.processOperation(op, TREASURY);
    expect(alert).toMatchObject({ severity: 'WARNING', invalidatedProposals: [] });
    expect(deps.markExpired).not.toHaveBeenCalled();
  });

  it('raises a WARNING when no proposal is affected', async () => {
    deps.loadTreasury.mockResolvedValue(null);
    expect(await watcher.processOperation(bumpOp('1000', '100'), TREASURY)).toMatchObject({ severity: 'WARNING' });
  });

  it('alerts only once for a replayed operation', async () => {
    const op = bumpOp('1000', '100');
    await watcher.processOperation(op, TREASURY);
    await expect(watcher.processOperation(op, TREASURY)).resolves.toBeNull();
    expect(deps.notify).toHaveBeenCalledTimes(1);
  });

  it('keeps proposals pending and retries when Horizon cannot confirm them', async () => {
    const op = bumpOp('1000', '100');
    deps.isOnLedger.mockRejectedValueOnce(new Error('Horizon 503'));
    await expect(watcher.processOperation(op, TREASURY)).rejects.toThrow('Horizon 503');
    expect(deps.notify).not.toHaveBeenCalled();
    expect(deps.markExpired).not.toHaveBeenCalled();

    await expect(watcher.processOperation(op, TREASURY)).resolves.toMatchObject({ severity: 'CRITICAL' });
  });

  it('holds the cursor on failure and advances it after success', async () => {
    stellarMock.getLatestOperationPagingToken.mockResolvedValue({ ok: true, token: '150' });
    await watcher.runPass([TREASURY]);
    expect(stellarMock.getAccountOperationsSince).not.toHaveBeenCalled();

    const op = bumpOp('1000', '100');
    stellarMock.getAccountOperationsSince.mockResolvedValue({ ok: true, records: [op] });
    deps.notify.mockRejectedValueOnce(new Error('delivery down'));
    await expect(watcher.runPass([TREASURY])).resolves.toBe(0);
    expect(stellarMock.getAccountOperationsSince).toHaveBeenLastCalledWith(TREASURY, '150', 100, {
      includeTransactions: true,
    });

    await expect(watcher.runPass([TREASURY])).resolves.toBe(1);
    stellarMock.getAccountOperationsSince.mockResolvedValue({ ok: true, records: [] });
    await watcher.runPass([TREASURY]);
    expect(stellarMock.getAccountOperationsSince).toHaveBeenLastCalledWith(TREASURY, '200', 100, {
      includeTransactions: true,
    });
  });

  it('caps the Telegram list of invalidated hashes', async () => {
    deps.loadTreasury.mockResolvedValue({
      proposals: Array.from({ length: 12 }, (_, index) => proposal(`p${index}`, String(200 + index))),
      signerUserIds: [],
    });
    const alert = await watcher.processOperation(bumpOp('1000', '100'), TREASURY);
    expect(buildSequenceTelegramMessage(alert!)).toContain('...and 2 more');
  });
});
