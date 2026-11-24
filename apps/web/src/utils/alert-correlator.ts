/**
 * Pure correlation and post-mortem generation for the incident timeline (#1044).
 * No DOM, React or network access: alerts go in, clusters and reports come out.
 */

export type AlertSeverity = 'info' | 'warning' | 'critical';

export interface CorrelatableAlert {
  id: string;
  title: string;
  severity: AlertSeverity;
  timestamp: string;
  walletId?: string;
  txHash?: string;
  counterparties: string[];
  amount?: number;
  asset?: string;
}

/** Accepts the web app's payment, cached-alert and triage shapes. */
export interface NormalizableAlert {
  id?: string;
  title?: string;
  message?: string;
  severity?: string | null;
  priority?: string | null;
  walletId?: string | null;
  txHash?: string | null;
  counterparty?: string | null;
  fromAddress?: string | null;
  destinationAddress?: string | null;
  amount?: number | string | null;
  asset?: string | null;
  timestamp?: string | Date | null;
  receivedAt?: string | Date | null;
  createdAt?: string | Date | null;
}

export interface CorrelationOptions {
  /** Default: five minutes, per issue #1044. */
  windowMs?: number;
}

export interface IncidentCluster {
  id: string;
  alerts: CorrelatableAlert[];
  startedAt: string;
  endedAt: string;
  severity: AlertSeverity;
  walletIds: string[];
  txHashes: string[];
  counterparties: string[];
  links: string[];
  valueAtRisk: Record<string, number>;
  valueAtRiskLabel: string;
}

const DEFAULT_WINDOW_MS = 5 * 60 * 1000;
const SEVERITY_RANK: Record<AlertSeverity, number> = { info: 0, warning: 1, critical: 2 };

function normalizeSeverity(value: string | null | undefined): AlertSeverity {
  const severity = (value ?? '').toLowerCase();
  if (['critical', 'high', 'error', 'urgent'].includes(severity)) return 'critical';
  if (['warning', 'medium', 'warn'].includes(severity)) return 'warning';
  return 'info';
}

function toTimestamp(value: string | Date | null | undefined): string | undefined {
  if (!value) return undefined;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : undefined;
}

export function normalizeAlert(input: NormalizableAlert, index = 0): CorrelatableAlert | null {
  const timestamp = toTimestamp(input.timestamp ?? input.receivedAt ?? input.createdAt);
  if (!timestamp) return null;

  const amount = Number(input.amount);
  const counterparties = [...new Set(
    [input.counterparty, input.fromAddress, input.destinationAddress]
      .filter((value): value is string => Boolean(value && value.trim())),
  )];

  return {
    id: input.id ?? `alert-${index}`,
    title: input.title ?? input.message ?? 'Security event',
    severity: normalizeSeverity(input.severity ?? input.priority),
    timestamp,
    walletId: input.walletId ?? undefined,
    txHash: input.txHash ?? undefined,
    counterparties,
    amount: Number.isFinite(amount) && amount > 0 ? amount : undefined,
    asset: input.asset ?? undefined,
  };
}

export function normalizeAlerts(inputs: readonly NormalizableAlert[]): CorrelatableAlert[] {
  return inputs
    .map((input, index) => normalizeAlert(input, index))
    .filter((alert): alert is CorrelatableAlert => alert !== null);
}

function sharedKey(left: CorrelatableAlert, right: CorrelatableAlert): string | undefined {
  if (left.txHash && left.txHash === right.txHash) return `tx:${left.txHash}`;
  if (left.walletId && left.walletId === right.walletId) return `wallet:${left.walletId}`;
  const counterparty = left.counterparties.find((address) => right.counterparties.includes(address));
  return counterparty ? `counterparty:${counterparty}` : undefined;
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

function buildCluster(alerts: CorrelatableAlert[], links: string[]): IncidentCluster {
  const ordered = [...alerts].sort((left, right) =>
    Date.parse(left.timestamp) - Date.parse(right.timestamp) || left.id.localeCompare(right.id));
  const severity = ordered.reduce<AlertSeverity>(
    (worst, alert) => SEVERITY_RANK[alert.severity] > SEVERITY_RANK[worst] ? alert.severity : worst,
    'info',
  );
  const valueAtRisk: Record<string, number> = {};
  for (const alert of ordered) {
    if (alert.amount === undefined) continue;
    const asset = alert.asset || 'UNKNOWN';
    valueAtRisk[asset] = (valueAtRisk[asset] ?? 0) + alert.amount;
  }

  return {
    id: `INC-${Date.parse(ordered[0].timestamp).toString(36)}-${ordered[0].id.slice(0, 6)}`,
    alerts: ordered,
    startedAt: ordered[0].timestamp,
    endedAt: ordered[ordered.length - 1].timestamp,
    severity,
    walletIds: uniqueSorted(ordered.map((alert) => alert.walletId).filter((value): value is string => Boolean(value))),
    txHashes: uniqueSorted(ordered.map((alert) => alert.txHash).filter((value): value is string => Boolean(value))),
    counterparties: uniqueSorted(ordered.flatMap((alert) => alert.counterparties)),
    links: uniqueSorted(links),
    valueAtRisk,
    valueAtRiskLabel: Object.entries(valueAtRisk)
      .sort(([leftAsset, leftAmount], [rightAsset, rightAmount]) =>
        rightAmount - leftAmount || leftAsset.localeCompare(rightAsset))
      .map(([asset, amount]) => `${amount} ${asset}`)
      .join(', ') || 'none',
  };
}

/**
 * Single-link clusters alerts that share a wallet, tx hash or counterparty
 * inside the rolling window. Inputs are never mutated.
 */
export function clusterAlerts(
  inputs: readonly CorrelatableAlert[],
  options: CorrelationOptions = {},
): IncidentCluster[] {
  const windowMs = options.windowMs ?? DEFAULT_WINDOW_MS;
  const alerts = [...inputs].sort((left, right) =>
    Date.parse(left.timestamp) - Date.parse(right.timestamp) || left.id.localeCompare(right.id));
  const parent = alerts.map((_, index) => index);
  const links = new Map<number, string[]>();

  const find = (index: number): number => {
    while (parent[index] !== index) {
      parent[index] = parent[parent[index]];
      index = parent[index];
    }
    return index;
  };
  const union = (left: number, right: number, key: string) => {
    const a = find(left);
    const b = find(right);
    if (a === b) return;
    const root = Math.min(a, b);
    parent[Math.max(a, b)] = root;
    const combined = [...(links.get(a) ?? []), ...(links.get(b) ?? []), key];
    links.delete(a);
    links.delete(b);
    links.set(root, combined);
  };

  for (let i = 0; i < alerts.length; i += 1) {
    for (let j = i + 1; j < alerts.length; j += 1) {
      if (Date.parse(alerts[j].timestamp) - Date.parse(alerts[i].timestamp) > windowMs) break;
      const key = sharedKey(alerts[i], alerts[j]);
      if (key) union(i, j, key);
    }
  }

  const groups = new Map<number, CorrelatableAlert[]>();
  alerts.forEach((alert, index) => {
    const root = find(index);
    groups.set(root, [...(groups.get(root) ?? []), alert]);
  });

  return [...groups.entries()]
    .map(([root, group]) => buildCluster(group, links.get(root) ?? []))
    .sort((left, right) => Date.parse(right.startedAt) - Date.parse(left.startedAt));
}

/** Self-contained Markdown post-mortem suitable for download or pasting into an issue. */
export function buildMarkdownPostMortem(cluster: IncidentCluster): string {
  const indicators = [
    ...cluster.walletIds.map((value) => `wallet \`${value}\``),
    ...cluster.txHashes.map((value) => `tx \`${value}\``),
    ...cluster.counterparties.map((value) => `counterparty \`${value}\``),
  ];

  return [
    `# Incident post-mortem: ${cluster.id}`,
    '',
    `- **Severity:** ${cluster.severity.toUpperCase()}`,
    `- **Window:** ${cluster.startedAt} — ${cluster.endedAt}`,
    `- **Alerts:** ${cluster.alerts.length}`,
    `- **Value at risk:** ${cluster.valueAtRiskLabel}`,
    `- **Shared indicators:** ${indicators.length > 0 ? indicators.join(', ') : 'none'}`,
    '',
    '## Timeline',
    ...cluster.alerts.map((alert, index) => [
      `${index + 1}. \`${alert.timestamp}\` **${alert.severity.toUpperCase()}** — ${alert.title}`,
      `   - ID: \`${alert.id}\``,
      alert.walletId ? `   - Wallet: \`${alert.walletId}\`` : '',
      alert.txHash ? `   - Transaction: \`${alert.txHash}\`` : '',
      alert.counterparties.length > 0 ? `   - Counterparties: ${alert.counterparties.map((value) => `\`${value}\``).join(', ')}` : '',
      alert.amount !== undefined ? `   - Amount: ${alert.amount} ${alert.asset ?? 'UNKNOWN'}` : '',
    ].filter(Boolean).join('\n')),
    '',
  ].join('\n');
}

/** Self-contained JSON post-mortem with the same data as the Markdown report. */
export function buildJsonPostMortem(cluster: IncidentCluster): string {
  return JSON.stringify({ schema: 'stellar-alerts/incident-postmortem/v1', ...cluster }, null, 2);
}
