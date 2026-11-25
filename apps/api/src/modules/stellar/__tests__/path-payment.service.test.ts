import { describe, expect, it } from 'vitest';
import * as StellarSdk from 'stellar-sdk';
import {
  buildPathPaymentAlertMetadata,
  decodePathPaymentOperation,
  decomposePathPayment,
} from '../path-payment.service';

const issuer = StellarSdk.Keypair.random().publicKey();
const destination = StellarSdk.Keypair.random().publicKey();

const USDC = new StellarSdk.Asset('USDC', issuer);
const USDT = new StellarSdk.Asset('USDT', issuer);
const EURC = new StellarSdk.Asset('EURC', issuer);
const BTC = new StellarSdk.Asset('BTC', issuer);

function strictSendXdr(path: StellarSdk.Asset[]): string {
  const op = StellarSdk.Operation.pathPaymentStrictSend({
    sendAsset: StellarSdk.Asset.native(),
    sendAmount: '100.0000000',
    destination,
    destAsset: USDC,
    destMin: '9.0000000',
    path,
  });
  return op.toXDR('base64' as any);
}

describe('PathPaymentDecomposer (#912)', () => {
  it('extracts an ordered 4-hop route from path payment XDR', () => {
    const xdr = strictSendXdr([USDT, EURC, BTC]);

    const decoded = decodePathPaymentOperation(xdr);

    expect(decoded.type).toBe('path_payment_strict_send');
    expect(decoded.destinationAccount).toBe(destination);
    expect(decoded.sendAsset).toBe('XLM');
    expect(decoded.destAsset).toBe(`USDC:${issuer}`);
    expect(decoded.path).toEqual([`USDT:${issuer}`, `EURC:${issuer}`, `BTC:${issuer}`]);
    expect(decoded.sendAmount).toBe('100.0000000');
    expect(decoded.destAmount).toBe('9.0000000');

    const flow = decomposePathPayment(xdr);
    expect(flow.hops).toHaveLength(4);
    expect(flow.hops.map((hop) => `${hop.fromAsset}>${hop.toAsset}`)).toEqual([
      `XLM>USDT:${issuer}`,
      `USDT:${issuer}>EURC:${issuer}`,
      `EURC:${issuer}>BTC:${issuer}`,
      `BTC:${issuer}>USDC:${issuer}`,
    ]);
  });

  it('attaches realized hop amounts and prices from trade data', () => {
    const xdr = strictSendXdr([USDT, EURC, BTC]);

    const flow = decomposePathPayment(xdr, {
      executedSourceAmount: '100.0000000',
      executedDestAmount: '10.0000000',
      hopAmounts: ['50.0000000', '25.0000000', '12.0000000', '10.0000000'],
    });

    expect(flow.hops[0]!.amountIn).toBe('100.0000000');
    expect(flow.hops[0]!.amountOut).toBe('50.0000000');
    expect(flow.hops[0]!.price).toBe(0.5);
    expect(flow.hops[3]!.amountOut).toBe('10.0000000');
    expect(flow.hops[3]!.price).toBeCloseTo(10 / 12, 6);
  });

  it('leaves intermediate amounts undefined when trade data is unavailable', () => {
    const flow = decomposePathPayment(strictSendXdr([USDT, EURC, BTC]), {
      executedSourceAmount: '100.0000000',
      executedDestAmount: '10.0000000',
    });

    expect(flow.hops[0]!.amountIn).toBe('100.0000000');
    expect(flow.hops[0]!.amountOut).toBeUndefined();
    expect(flow.hops[1]!.amountIn).toBeUndefined();
    expect(flow.hops[1]!.amountOut).toBeUndefined();
    expect(flow.hops[3]!.amountOut).toBe('10.0000000');
  });

  it('calculates effective execution price and arbitrage against a spot reference', () => {
    const flow = decomposePathPayment(strictSendXdr([USDT, EURC, BTC]), {
      executedSourceAmount: '100.0000000',
      executedDestAmount: '10.0000000',
      spotPrice: 0.09,
    });

    expect(flow.effectivePrice).toBe(0.1);
    expect(flow.spotPrice).toBe(0.09);
    expect(flow.arbitrageBps).toBeCloseTo(1111.11, 2);
    expect(flow.exceedsArbitrageThreshold).toBe(true);
  });

  it('flags a value-losing route as not exceeding the arbitrage threshold', () => {
    const flow = decomposePathPayment(strictSendXdr([USDT]), {
      executedSourceAmount: '100.0000000',
      executedDestAmount: '8.0000000',
      spotPrice: 0.09,
    });

    expect(flow.arbitrageBps).toBeCloseTo(-1111.11, 2);
    expect(flow.exceedsArbitrageThreshold).toBe(false);
  });

  it('builds conversion-path visualization metadata for alert payloads', () => {
    const flow = decomposePathPayment(strictSendXdr([USDT, EURC, BTC]), {
      executedSourceAmount: '100.0000000',
      executedDestAmount: '10.0000000',
    });

    const metadata = buildPathPaymentAlertMetadata(flow);

    expect(metadata.pathVisualization.nodes).toEqual([
      'XLM',
      `USDT:${issuer}`,
      `EURC:${issuer}`,
      `BTC:${issuer}`,
      `USDC:${issuer}`,
    ]);
    expect(metadata.pathVisualization.edges).toHaveLength(4);
    expect(metadata.pathVisualization.edges[2]).toEqual({
      from: `EURC:${issuer}`,
      to: `BTC:${issuer}`,
      hopIndex: 2,
    });
  });

  it('decodes strict receive operations using the max send amount', () => {
    const op = StellarSdk.Operation.pathPaymentStrictReceive({
      sendAsset: StellarSdk.Asset.native(),
      sendMax: '120.0000000',
      destination,
      destAsset: USDC,
      destAmount: '10.0000000',
      path: [USDT, EURC, BTC],
    });

    const decoded = decodePathPaymentOperation(op.toXDR('base64' as any));

    expect(decoded.type).toBe('path_payment_strict_receive');
    expect(decoded.sendAmount).toBe('10.0000000'); // exact destination amount
    expect(decoded.destAmount).toBe('120.0000000'); // maximum willing to send
  });

  it('rejects non-path-payment operations and malformed hop amounts', () => {
    const payment = StellarSdk.Operation.payment({
      destination,
      asset: StellarSdk.Asset.native(),
      amount: '1.0000000',
    });
    expect(() => decodePathPaymentOperation(payment.toXDR('base64' as any))).toThrow(/not a path payment/);

    expect(() =>
      decomposePathPayment(strictSendXdr([USDT, EURC, BTC]), { hopAmounts: ['1', '2'] }),
    ).toThrow(/hopAmounts/);
  });
});
