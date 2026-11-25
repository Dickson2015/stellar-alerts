/**
 * PathPaymentDecomposer (#912)
 *
 * Decodes path payment operations (strict send / strict receive) from their
 * Stellar XDR, decomposes them into the ordered sequence of intermediate asset
 * conversions ("hops"), and derives the effective execution price so alert
 * payloads can show exactly which order books / pools a payment crossed and
 * how much value was lost or gained against a reference spot price.
 */

import * as StellarSdk from 'stellar-sdk';

export type PathPaymentType = 'path_payment_strict_send' | 'path_payment_strict_receive';

/** One asset conversion in a path payment route. */
export interface PathPaymentHop {
  /** Zero-based hop position. */
  index: number;
  fromAsset: string;
  toAsset: string;
  /** Amount entering this hop, when known (first hop always knows its input). */
  amountIn?: string;
  /** Amount leaving this hop, when known (last hop always knows its output). */
  amountOut?: string;
  /** amountOut / amountIn for this hop, when both are known. */
  price?: number;
}

export interface DecodedPathPayment {
  type: PathPaymentType;
  /** Operation-level source account, if the operation overrides the transaction source. */
  sourceAccount: string | null;
  destinationAccount: string;
  sendAsset: string;
  destAsset: string;
  /** Ordered intermediate assets (excluding send/dest assets). */
  path: string[];
  /** strict_send: exact amount sent. strict_receive: exact amount to receive. */
  sendAmount: string;
  /** strict_send: minimum amount to receive. strict_receive: maximum amount to send. */
  destAmount: string;
  /** The operation's XDR, retained for downstream audit / debugging. */
  operationXdr: string;
}

export interface PathPaymentDecompositionOptions {
  /** Actual amount debited from the source account, from Horizon's operation record. */
  executedSourceAmount?: string;
  /** Actual amount credited to the destination, from Horizon's operation record. */
  executedDestAmount?: string;
  /** Intermediate hop outputs (length must equal the hop count) from trade records. */
  hopAmounts?: string[];
  /** Reference spot price in destination units per source unit. */
  spotPrice?: number;
  /** Arbitrage threshold in basis points. Defaults to 50 bps. */
  arbitrageThresholdBps?: number;
}

export interface PathPaymentFlow {
  type: PathPaymentType;
  sourceAccount: string | null;
  destinationAccount: string;
  sendAsset: string;
  destAsset: string;
  path: string[];
  hops: PathPaymentHop[];
  /** Total amount debited from the source (executed when provided). */
  totalSourceAmount: string;
  /** Total amount credited to the destination (executed when provided). */
  totalDestAmount: string;
  /** actual dest per source, only when both executed amounts are known. */
  effectivePrice: number | null;
  /** Reference price in dest per source, when supplied. */
  spotPrice: number | null;
  /** (effectivePrice / spotPrice - 1) * 10_000; positive means better than spot. */
  arbitrageBps: number | null;
  exceedsArbitrageThreshold: boolean;
  operationXdr: string;
}

const STROOPS_PER_UNIT = 10_000_000;
const DEFAULT_ARBITRAGE_THRESHOLD_BPS = 50;

function amountFromXdrAmount(value: StellarSdk.xdr.Int64 | bigint | string | number): string {
  const raw = BigInt(value.toString());
  const whole = raw / BigInt(STROOPS_PER_UNIT);
  const fraction = (raw % BigInt(STROOPS_PER_UNIT)).toString().padStart(7, '0');
  return `${whole}.${fraction}`;
}

function assetToString(asset: StellarSdk.xdr.Asset): string {
  try {
    const resolved = StellarSdk.Asset.fromOperation(asset);
    // `native` is stellar-sdk's spelling; the rest of this codebase uses XLM.
    return resolved.isNative() ? 'XLM' : resolved.toString();
  } catch {
    return 'UNKNOWN';
  }
}

function accountFromMuxed(account: StellarSdk.xdr.MuxedAccount | null | undefined): string | null {
  if (!account) return null;
  try {
    const ed25519 = account.ed25519();
    if (ed25519) return StellarSdk.StrKey.encodeEd25519PublicKey(Buffer.from(ed25519));
  } catch {
    // Muxed (M...) accounts have no ed25519() accessor; fall back to null.
  }
  return null;
}

/** Decodes a base64 operation XDR into a path payment description. */
export function decodePathPaymentOperation(operationXdr: string): DecodedPathPayment {
  const operation = StellarSdk.xdr.Operation.fromXDR(operationXdr, 'base64');
  const switchName = operation.body().switch().name;

  if (switchName !== 'pathPaymentStrictSend' && switchName !== 'pathPaymentStrictReceive') {
    throw new Error(
      `Operation is ${switchName}, not a path payment (expected pathPaymentStrictSend or pathPaymentStrictReceive)`,
    );
  }

  const sourceAccount = accountFromMuxed(operation.sourceAccount() ?? undefined);

  if (switchName === 'pathPaymentStrictSend') {
    const op = operation.body().value() as StellarSdk.xdr.PathPaymentStrictSendOp;
    return {
      type: 'path_payment_strict_send',
      sourceAccount,
      destinationAccount: accountFromMuxed(op.destination()) ?? '',
      sendAsset: assetToString(op.sendAsset()),
      destAsset: assetToString(op.destAsset()),
      path: op.path().map(assetToString),
      sendAmount: amountFromXdrAmount(op.sendAmount()),
      destAmount: amountFromXdrAmount(op.destMin()),
      operationXdr,
    };
  }

  const op = operation.body().value() as StellarSdk.xdr.PathPaymentStrictReceiveOp;
  return {
    type: 'path_payment_strict_receive',
    sourceAccount,
    destinationAccount: accountFromMuxed(op.destination()) ?? '',
    sendAsset: assetToString(op.sendAsset()),
    destAsset: assetToString(op.destAsset()),
    path: op.path().map(assetToString),
    sendAmount: amountFromXdrAmount(op.destAmount()),
    destAmount: amountFromXdrAmount(op.sendMax()),
    operationXdr,
  };
}

/**
 * Builds the ordered hop sequence sendAsset → path[0] → … → destAsset.
 *
 * Amounts are only attached when they can be known honestly: the first hop's
 * input and the last hop's output come from the executed operation record, and
 * intermediate amounts require per-hop trade data (`hopAmounts`). Missing
 * amounts stay undefined rather than being estimated.
 */
export function buildPathPaymentHops(
  decoded: Pick<DecodedPathPayment, 'sendAsset' | 'destAsset' | 'path'>,
  amounts: { totalSourceAmount?: string; totalDestAmount?: string; hopAmounts?: string[] } = {},
): PathPaymentHop[] {
  const assets = [decoded.sendAsset, ...decoded.path, decoded.destAsset];
  const hopCount = assets.length - 1;

  if (amounts.hopAmounts && amounts.hopAmounts.length !== hopCount) {
    throw new Error(
      `hopAmounts has ${amounts.hopAmounts.length} entries but the path has ${hopCount} hops`,
    );
  }

  const hops: PathPaymentHop[] = [];
  for (let i = 0; i < hopCount; i++) {
    const hop: PathPaymentHop = {
      index: i,
      fromAsset: assets[i]!,
      toAsset: assets[i + 1]!,
    };

    const amountIn = i === 0 ? amounts.totalSourceAmount : amounts.hopAmounts?.[i - 1];
    const amountOut = amounts.hopAmounts?.[i] ?? (i === hopCount - 1 ? amounts.totalDestAmount : undefined);

    if (amountIn !== undefined) hop.amountIn = amountIn;
    if (amountOut !== undefined) hop.amountOut = amountOut;

    const inValue = amountIn !== undefined ? Number(amountIn) : NaN;
    const outValue = amountOut !== undefined ? Number(amountOut) : NaN;
    if (Number.isFinite(inValue) && inValue > 0 && Number.isFinite(outValue)) {
      hop.price = outValue / inValue;
    }

    hops.push(hop);
  }

  return hops;
}

/** Decomposes a path payment operation into a flow with hop and pricing data. */
export function decomposePathPayment(
  operationXdr: string,
  options: PathPaymentDecompositionOptions = {},
): PathPaymentFlow {
  const decoded = decodePathPaymentOperation(operationXdr);

  const totalSourceAmount = options.executedSourceAmount ?? decoded.sendAmount;
  const totalDestAmount = options.executedDestAmount ?? decoded.destAmount;

  const hops = buildPathPaymentHops(decoded, {
    totalSourceAmount,
    totalDestAmount,
    hopAmounts: options.hopAmounts,
  });

  const sourceValue = Number(totalSourceAmount);
  const destValue = Number(totalDestAmount);
  const effectivePrice =
    Number.isFinite(sourceValue) && sourceValue > 0 && Number.isFinite(destValue)
      ? destValue / sourceValue
      : null;

  const spotPrice = options.spotPrice !== undefined && options.spotPrice > 0 ? options.spotPrice : null;
  const arbitrageBps =
    effectivePrice !== null && spotPrice !== null
      ? Math.round(((effectivePrice / spotPrice) - 1) * 10_000 * 100) / 100
      : null;

  const threshold = options.arbitrageThresholdBps ?? DEFAULT_ARBITRAGE_THRESHOLD_BPS;

  return {
    type: decoded.type,
    sourceAccount: decoded.sourceAccount,
    destinationAccount: decoded.destinationAccount,
    sendAsset: decoded.sendAsset,
    destAsset: decoded.destAsset,
    path: decoded.path,
    hops,
    totalSourceAmount,
    totalDestAmount,
    effectivePrice,
    spotPrice,
    arbitrageBps,
    exceedsArbitrageThreshold: arbitrageBps !== null && arbitrageBps >= threshold,
    operationXdr,
  };
}

export interface PathPaymentVisualization {
  nodes: string[];
  edges: Array<{ from: string; to: string; hopIndex: number }>;
}

export interface PathPaymentAlertMetadata {
  type: PathPaymentType;
  sendAsset: string;
  destAsset: string;
  totalSourceAmount: string;
  totalDestAmount: string;
  effectivePrice: number | null;
  spotPrice: number | null;
  arbitrageBps: number | null;
  exceedsArbitrageThreshold: boolean;
  hops: PathPaymentHop[];
  pathVisualization: PathPaymentVisualization;
}

/**
 * Builds the visualization metadata attached to alert payloads. Nodes are
 * de-duplicated asset codes in traversal order; edges preserve every hop so a
 * route that revisits an asset still renders each leg.
 */
export function buildPathPaymentAlertMetadata(flow: PathPaymentFlow): PathPaymentAlertMetadata {
  const nodes: string[] = [];
  for (const hop of flow.hops) {
    if (nodes.length === 0) nodes.push(hop.fromAsset);
    nodes.push(hop.toAsset);
  }

  return {
    type: flow.type,
    sendAsset: flow.sendAsset,
    destAsset: flow.destAsset,
    totalSourceAmount: flow.totalSourceAmount,
    totalDestAmount: flow.totalDestAmount,
    effectivePrice: flow.effectivePrice,
    spotPrice: flow.spotPrice,
    arbitrageBps: flow.arbitrageBps,
    exceedsArbitrageThreshold: flow.exceedsArbitrageThreshold,
    hops: flow.hops,
    pathVisualization: {
      nodes,
      edges: flow.hops.map((hop) => ({
        from: hop.fromAsset,
        to: hop.toAsset,
        hopIndex: hop.index,
      })),
    },
  };
}

export default {
  decodePathPaymentOperation,
  buildPathPaymentHops,
  decomposePathPayment,
  buildPathPaymentAlertMetadata,
};
