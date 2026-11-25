import * as StellarSdk from 'stellar-sdk';
import { env } from '../config/env';
import { prisma } from '../lib/prisma';
import { getContractInstanceLedgerKey, getWasmHashFromContractInstance, sorobanServer } from '../lib/soroban';
import { deliverUserAlert } from '../modules/stellar/alert-delivery';
import {
  projectRentExhaustion,
  type RentNetworkConfig,
  type RentObservation,
  type RentWarningTier,
} from '../modules/soroban/rent-predictor.service';
import { registerSupervisorHeartbeat } from './supervisor';

const POLL_INTERVAL_MS = Number(env.SOROBAN_RENT_WORKER_INTERVAL_MS);
const LEDGER_CLOSE_TIME_SECONDS = 5;
const WARNING_RANK: Record<RentWarningTier, number> = {
  '14_DAYS': 1,
  '7_DAYS': 2,
  '48_HOURS': 3,
};

let isProcessing = false;

function getRentNetworkConfig(settings: StellarSdk.xdr.StateArchivalSettings): RentNetworkConfig {
  return {
    ledgerCloseTimeSeconds: LEDGER_CLOSE_TIME_SECONDS,
    persistentRentRateDenominator: BigInt(settings.persistentRentRateDenominator().toString()),
    temporaryRentRateDenominator: BigInt(settings.tempRentRateDenominator().toString()),
  };
}

export async function fetchRentNetworkConfig(): Promise<RentNetworkConfig> {
  const configKey = StellarSdk.xdr.LedgerKey.configSetting(
    new StellarSdk.xdr.LedgerKeyConfigSetting({
      configSettingId: StellarSdk.xdr.ConfigSettingId.configSettingStateArchival(),
    }),
  );
  const response = await sorobanServer.getLedgerEntries(configKey);
  const configEntry = response.entries[0]?.val;
  if (!configEntry || configEntry.switch() !== StellarSdk.xdr.LedgerEntryType.configSetting()) {
    throw new Error('Soroban RPC did not return the state archival network configuration');
  }
  const settings = configEntry.configSetting().stateArchivalSettings();
  if (!settings) throw new Error('Soroban state archival settings are missing');
  return getRentNetworkConfig(settings);
}

function entryByteSize(entry: { val?: StellarSdk.xdr.LedgerEntryData }): number {
  if (!entry.val) throw new Error('Soroban RPC returned a ledger entry without XDR data');
  return entry.val.toXDR().byteLength;
}

async function observeContract(contractId: string): Promise<RentObservation[]> {
  const instanceKey = getContractInstanceLedgerKey(contractId);
  const instanceResponse = await sorobanServer.getLedgerEntries(instanceKey);
  const instance = instanceResponse.entries[0];
  if (!instance) return [];

  const observed: RentObservation[] = [{
    key: instanceKey.toXDR('hex'),
    durability: 'INSTANCE',
    byteSize: entryByteSize(instance),
    liveUntilLedgerSeq: instance.liveUntilLedgerSeq ?? 0,
  }];
  const wasmHash = getWasmHashFromContractInstance(instance.val);
  if (!wasmHash) return observed;

  const codeKey = StellarSdk.xdr.LedgerKey.contractCode(
    new StellarSdk.xdr.LedgerKeyContractCode({ hash: wasmHash }),
  );
  const codeEntry = (await sorobanServer.getLedgerEntries(codeKey)).entries[0];
  if (codeEntry) {
    observed.push({
      key: codeKey.toXDR('hex'),
      durability: 'PERSISTENT',
      byteSize: entryByteSize(codeEntry),
      liveUntilLedgerSeq: codeEntry.liveUntilLedgerSeq ?? 0,
    });
  }
  return observed;
}

function warningMessage(
  contractId: string,
  entry: RentObservation,
  projection: ReturnType<typeof projectRentExhaustion>,
): { payload: Record<string, unknown>; text: string } {
  const duration = projection.warningTier === '48_HOURS' ? '48 hours' : projection.warningTier === '7_DAYS' ? '7 days' : '14 days';
  return {
    payload: {
      event: 'soroban.rent_exhaustion_warning',
      severity: projection.warningTier === '48_HOURS' ? 'CRITICAL' : 'WARNING',
      contractId,
      ledgerKey: entry.key,
      durability: entry.durability,
      warningTier: projection.warningTier,
      projectedArchivalAt: projection.archivalAt.toISOString(),
      daysUntilArchival: projection.daysUntilArchival,
      byteGrowthPerDay: projection.byteGrowthPerDay,
      projectedBytesAtArchival: projection.projectedBytesAtArchival,
      renewalCostsXlm: projection.extensionCostsXlm,
    },
    text:
      `Soroban contract ${contractId} storage may be archived in ${duration}. ` +
      `Estimated renewal cost (30/90/180 days): ${projection.extensionCostsXlm[30]} / ` +
      `${projection.extensionCostsXlm[90]} / ${projection.extensionCostsXlm[180]} XLM.`,
  };
}

export async function runRentPredictionPass(): Promise<void> {
  const [subscriptions, latest, networkConfig] = await Promise.all([
    prisma.sorobanContractSubscription.findMany({
      where: { isActive: true },
      select: { contractId: true, userId: true },
    }),
    sorobanServer.getLatestLedger(),
    fetchRentNetworkConfig(),
  ]);
  const subscribers = new Map<string, Set<string>>();
  for (const subscription of subscriptions) {
    const userIds = subscribers.get(subscription.contractId) ?? new Set<string>();
    userIds.add(subscription.userId);
    subscribers.set(subscription.contractId, userIds);
  }

  for (const [contractId, userIds] of subscribers) {
    try {
      const observedEntries = await observeContract(contractId);
      for (const entry of observedEntries) {
        const existing = await prisma.sorobanRentObservation.findUnique({
          where: { contractId_ledgerKey: { contractId, ledgerKey: entry.key } },
        });
        const previousByteSize = existing?.byteSize ?? entry.byteSize;
        const previousLedgerSeq = existing?.ledgerSeq ?? latest.sequence;
        const ledgersBetweenSamples = latest.sequence - previousLedgerSeq;
        const projection = projectRentExhaustion(
          {
            currentLedger: latest.sequence,
            liveUntilLedgerSeq: entry.liveUntilLedgerSeq,
            currentByteSize: entry.byteSize,
            previousByteSize,
            ledgersBetweenSamples: Math.max(1, ledgersBetweenSamples),
          },
          entry.durability,
          networkConfig,
        );

        const oldTier = existing?.warningTier as RentWarningTier | null | undefined;
        const newTier = projection.warningTier;
        if (newTier && (!oldTier || WARNING_RANK[newTier] > WARNING_RANK[oldTier])) {
          const alert = warningMessage(contractId, entry, projection);
          for (const userId of userIds) {
            await deliverUserAlert(userId, alert.payload, alert.text);
          }
        }

        await prisma.sorobanRentObservation.upsert({
          where: { contractId_ledgerKey: { contractId, ledgerKey: entry.key } },
          create: {
            contractId,
            ledgerKey: entry.key,
            durability: entry.durability,
            byteSize: entry.byteSize,
            liveUntilLedgerSeq: entry.liveUntilLedgerSeq,
            ledgerSeq: latest.sequence,
            warningTier: newTier,
          },
          update: {
            durability: entry.durability,
            previousByteSize: existing?.byteSize ?? null,
            previousLedgerSeq: existing?.ledgerSeq ?? null,
            byteSize: entry.byteSize,
            liveUntilLedgerSeq: entry.liveUntilLedgerSeq,
            ledgerSeq: latest.sequence,
            warningTier: newTier ?? oldTier ?? null,
          },
        });
      }
    } catch (error) {
      console.error(
        `[RentPredictorWorker] Failed to assess contract ${contractId}:`,
        error instanceof Error ? error.message : error,
      );
    }
  }
}

export async function runRentPredictorWorker(): Promise<void> {
  const poll = async () => {
    if (isProcessing) return;
    isProcessing = true;
    try {
      await runRentPredictionPass();
    } catch (error) {
      console.error(
        '[RentPredictorWorker] Prediction pass failed:',
        error instanceof Error ? error.message : error,
      );
    } finally {
      isProcessing = false;
    }
  };

  await poll();
  setInterval(() => void poll(), POLL_INTERVAL_MS);
}

if (require.main === module) {
  registerSupervisorHeartbeat();
  void runRentPredictorWorker();
}
