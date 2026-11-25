import { describe, it, expect } from 'vitest';
import * as StellarSdk from 'stellar-sdk';
import {
  FeeBumpSentinel,
  extractFeeBumpEnvelope,
  type FeeBumpObservation,
} from '../feebump-sentinel';

const PASSPHRASE = StellarSdk.Networks.TESTNET;

function buildFeeBumpXdr(opCount = 2) {
  const inner = StellarSdk.Keypair.random();
  const sponsor = StellarSdk.Keypair.random();
  const account = new StellarSdk.Account(inner.publicKey(), '1');
  const builder = new StellarSdk.TransactionBuilder(account, { fee: '100', networkPassphrase: PASSPHRASE });
  for (let i = 0; i < opCount; i++) {
    builder.addOperation(
      StellarSdk.Operation.payment({
        destination: StellarSdk.Keypair.random().publicKey(),
        asset: StellarSdk.Asset.native(),
        amount: '1',
      }),
    );
  }
  const tx = builder.setTimeout(30).build();
  tx.sign(inner);
  const bump = StellarSdk.TransactionBuilder.buildFeeBumpTransaction(sponsor, '400', tx, PASSPHRASE);
  bump.sign(sponsor);
  return { xdr: bump.toXDR(), inner: inner.publicKey(), sponsor: sponsor.publicKey(), innerHash: tx.hash().toString('hex') };
}

function obs(over: Partial<FeeBumpObservation> = {}): FeeBumpObservation {
  return {
    txHash: 'tx',
    innerTxHash: 'inner',
    feeSource: 'GSPONSOR',
    innerSource: 'GUSER',
    feeChargedStroops: 1_000n,
    operationCount: 1,
    innerSucceeded: true,
    observedAt: 1_000_000,
    ...over,
  };
}

describe('FeeBumpSentinel (#978)', () => {
  describe('envelope unwrapping', () => {
    it('extracts both the outer feeSource and the inner source account', () => {
      const { xdr, inner, sponsor, innerHash } = buildFeeBumpXdr(3);
      const info = extractFeeBumpEnvelope(xdr, PASSPHRASE);
      expect(info?.feeSource).toBe(sponsor);
      expect(info?.innerSource).toBe(inner);
      expect(info?.innerTxHash).toBe(innerHash);
      expect(info?.operationCount).toBe(3);
      // buildFeeBumpTransaction takes a per-operation base fee: 400 x (3 inner ops + 1 bump) stroops.
      expect(info?.maxFeeStroops).toBe(1600n);
    });

    it('returns null for a plain transaction envelope and for garbage', () => {
      const account = new StellarSdk.Account(StellarSdk.Keypair.random().publicKey(), '1');
      const plain = new StellarSdk.TransactionBuilder(account, { fee: '100', networkPassphrase: PASSPHRASE })
        .addOperation(StellarSdk.Operation.bumpSequence({ bumpTo: '10' }))
        .setTimeout(30)
        .build();
      expect(extractFeeBumpEnvelope(plain.toXDR(), PASSPHRASE)).toBeNull();
      expect(extractFeeBumpEnvelope('not-xdr', PASSPHRASE)).toBeNull();
    });

    it('builds an observation from a Horizon record using fee_charged', () => {
      const { xdr, sponsor, inner } = buildFeeBumpXdr(2);
      const sentinel = new FeeBumpSentinel();
      const o = sentinel.observationFromHorizon(
        { hash: 'abc', successful: false, fee_account: sponsor, fee_charged: '300', envelope_xdr: xdr },
        PASSPHRASE,
      );
      expect(o).toMatchObject({ feeSource: sponsor, innerSource: inner, feeChargedStroops: 300n, operationCount: 2, innerSucceeded: false });
    });

    it('ignores ordinary transactions', () => {
      const sentinel = new FeeBumpSentinel();
      expect(sentinel.observationFromHorizon({ hash: 'x', operation_count: 1 }, PASSPHRASE)).toBeNull();
    });
  });

  describe('rolling one-hour fee burn', () => {
    it('sums XLM spent per sponsor and drops observations older than the window', () => {
      let now = 1_000_000;
      const sentinel = new FeeBumpSentinel({}, () => now);
      sentinel.record(obs({ feeChargedStroops: 10_000_000n, observedAt: now }));
      sentinel.record(obs({ feeSource: 'GOTHER', feeChargedStroops: 5_000_000n, observedAt: now }));
      expect(sentinel.getStats('GSPONSOR').feeBurnXlm).toBe(1);
      expect(sentinel.getStats('GOTHER').feeBurnXlm).toBe(0.5);

      now += 61 * 60 * 1000;
      expect(sentinel.getStats('GSPONSOR').feeBurnXlm).toBe(0);
      expect(sentinel.getStats('GSPONSOR').txCount).toBe(0);
    });
  });

  describe('alerting', () => {
    it('alerts when average fee per operation exceeds 10,000 stroops', () => {
      const sentinel = new FeeBumpSentinel({}, () => 1_000_000);
      expect(sentinel.record(obs({ feeChargedStroops: 10_000n, operationCount: 1 }))).toHaveLength(0);
      const alerts = sentinel.record(obs({ feeChargedStroops: 50_000n, operationCount: 1 }));
      expect(alerts.map((a) => a.type)).toEqual(['FEE_SURGE']);
      expect(alerts[0].avgFeePerOpStroops).toBe(30_000);
    });

    it('alerts when the failed inner transaction ratio exceeds 15%', () => {
      const sentinel = new FeeBumpSentinel({}, () => 1_000_000);
      let last = [] as ReturnType<typeof sentinel.record>;
      for (let i = 0; i < 8; i++) last = sentinel.record(obs({ innerSucceeded: true }));
      expect(last).toHaveLength(0);
      sentinel.record(obs({ innerSucceeded: false }));
      last = sentinel.record(obs({ innerSucceeded: false }));
      expect(last.map((a) => a.type)).toEqual(['INNER_FAILURE_RATIO']);
      expect(last[0].failedInnerRatio).toBeCloseTo(0.2);
    });

    it('does not alert on a failure ratio with too few samples', () => {
      const sentinel = new FeeBumpSentinel({}, () => 1_000_000);
      expect(sentinel.record(obs({ innerSucceeded: false }))).toHaveLength(0);
    });

    it('does not alert at exactly the thresholds', () => {
      const sentinel = new FeeBumpSentinel({}, () => 1_000_000);
      expect(sentinel.record(obs({ feeChargedStroops: 10_000n, operationCount: 1 }))).toHaveLength(0);
    });

    it('suppresses repeated alerts inside the cooldown and notifies subscribers', async () => {
      let now = 1_000_000;
      const sentinel = new FeeBumpSentinel({}, () => now);
      const received: string[] = [];
      sentinel.subscribe((a) => { received.push(a.type); });

      const surge = () => obs({ feeChargedStroops: 90_000n, observedAt: now });
      expect(sentinel.record(surge())).toHaveLength(1);
      expect(sentinel.record(surge())).toHaveLength(0);
      now += 11 * 60 * 1000;
      expect(sentinel.record(surge())).toHaveLength(1);

      await Promise.resolve();
      await Promise.resolve();
      expect(received).toEqual(['FEE_SURGE', 'FEE_SURGE']);
    });
  });
});
