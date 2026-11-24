import { describe, expect, it } from 'vitest';
import {
  buildJsonPostMortem,
  buildMarkdownPostMortem,
  clusterAlerts,
  normalizeAlert,
  normalizeAlerts,
  type CorrelatableAlert,
} from './alert-correlator';

const BASE = '2026-11-24T10:00:00.000Z';

function at(seconds: number): string {
  return new Date(Date.parse(BASE) + seconds * 1000).toISOString();
}

function alert(id: string, overrides: Partial<CorrelatableAlert> = {}): CorrelatableAlert {
  return {
    id,
    title: `Alert ${id}`,
    severity: 'info',
    timestamp: at(Number(id.replace(/\D/g, '')) || 0),
    counterparties: [],
    ...overrides,
  };
}

describe('normalizeAlert (#1044)', () => {
  it('normalizes payments, triage alerts and shared priorities', () => {
    expect(normalizeAlert({
      id: 'p1',
      amount: '12.5',
      asset: 'XLM',
      fromAddress: 'GATTACKER',
      receivedAt: BASE,
    })).toEqual({
      id: 'p1',
      title: 'Security event',
      severity: 'info',
      timestamp: BASE,
      walletId: undefined,
      txHash: undefined,
      counterparties: ['GATTACKER'],
      amount: 12.5,
      asset: 'XLM',
    });

    expect(normalizeAlert({ id: 'a1', priority: 'CRITICAL', severity: 'warning', timestamp: BASE })?.severity)
      .toBe('warning');
    expect(normalizeAlert({ id: 'a2', priority: 'HIGH', timestamp: BASE })?.severity).toBe('critical');
    expect(normalizeAlert({ id: 'a3', amount: Number.NaN, receivedAt: 'not-a-date' })).toBeNull();
    expect(normalizeAlerts([{ id: 'ok', timestamp: BASE }, { id: 'bad' }])).toHaveLength(1);
  });
});

describe('clusterAlerts (#1044)', () => {
  it('clusters alerts sharing a transaction hash and escalates severity', () => {
    const clusters = clusterAlerts([
      alert('1', { severity: 'info', txHash: 'tx-1', walletId: 'w1' }),
      alert('2', { severity: 'critical', txHash: 'tx-1', walletId: 'w2' }),
      alert('3', { severity: 'warning', txHash: 'tx-2', walletId: 'w3' }),
    ]);

    expect(clusters).toHaveLength(2);
    const incident = clusters.find((cluster) => cluster.txHashes.includes('tx-1'))!;
    expect(incident).toMatchObject({
      severity: 'critical',
      alerts: [{ id: '1' }, { id: '2' }],
      txHashes: ['tx-1'],
      links: ['tx:tx-1'],
    });
    expect(incident.startedAt).toBe(at(1));
    expect(incident.endedAt).toBe(at(2));
  });

  it('clusters by counterparty and by wallet inside the window', () => {
    const clusters = clusterAlerts([
      alert('1', { counterparties: ['GATTACKER'], walletId: 'w1' }),
      alert('2', { counterparties: ['GATTACKER'], walletId: 'w2', timestamp: at(299) }),
      alert('3', { counterparties: ['GHOLDER'], walletId: 'w1', timestamp: at(300) }),
      alert('4', { counterparties: ['GHOLDER'], walletId: 'w1', timestamp: at(301) }),
    ]);

    expect(clusters).toHaveLength(1);
    expect(clusters[0].alerts.map((entry) => entry.id)).toEqual(['1', '2', '3', '4']);
    expect(clusters[0].counterparties).toEqual(['GATTACKER', 'GHOLDER']);
    expect(clusters[0].walletIds).toEqual(['w1', 'w2']);
  });

  it('splits clusters when the gap exceeds the configurable window', () => {
    const alerts = [
      alert('1', { txHash: 'tx-1', timestamp: at(0) }),
      alert('2', { txHash: 'tx-1', timestamp: at(301) }),
    ];

    expect(clusterAlerts(alerts)).toHaveLength(2);
    expect(clusterAlerts(alerts, { windowMs: 400_000 })).toHaveLength(1);
  });

  it('never clusters unrelated alerts that merely overlap in time', () => {
    expect(clusterAlerts([
      alert('1', { timestamp: at(0) }),
      alert('2', { timestamp: at(10) }),
    ])).toHaveLength(2);
  });

  it('totals value at risk per asset without mixing currencies', () => {
    const [cluster] = clusterAlerts([
      alert('1', { txHash: 'tx-1', amount: 100, asset: 'XLM' }),
      alert('2', { txHash: 'tx-1', amount: 50, asset: 'XLM' }),
      alert('3', { txHash: 'tx-1', amount: 25, asset: 'USDC' }),
    ]);

    expect(cluster.valueAtRisk).toEqual({ USDC: 25, XLM: 150 });
    expect(cluster.valueAtRiskLabel).toBe('150 XLM, 25 USDC');
  });

  it('does not mutate its inputs', () => {
    const alerts = [alert('1', { txHash: 'tx-1' }), alert('2', { txHash: 'tx-1', timestamp: at(5) })];
    const snapshot = JSON.stringify(alerts);
    clusterAlerts(alerts);
    expect(JSON.stringify(alerts)).toBe(snapshot);
  });
});

describe('post-mortem generation (#1044)', () => {
  const [cluster] = clusterAlerts([
    alert('1', { severity: 'warning', txHash: 'tx-1', walletId: 'w1', amount: 100, asset: 'XLM' }),
    alert('2', { severity: 'critical', txHash: 'tx-1', counterparties: ['GATTACKER'], timestamp: at(30) }),
  ]);

  it('Builds a self-contained Markdown timeline with severity and value at risk', () => {
    const markdown = buildMarkdownPostMortem(cluster);

    expect(markdown).toContain(`# Incident post-mortem: ${cluster.id}`);
    expect(markdown).toContain('- **Severity:** CRITICAL');
    expect(markdown).toContain('- **Value at risk:** 100 XLM');
    expect(markdown).toContain('- **Shared indicators:** wallet `w1`, tx `tx-1`, counterparty `GATTACKER`');
    expect(markdown).toContain('## Timeline');
    expect(markdown.indexOf('Alert 1')).toBeLessThan(markdown.indexOf('Alert 2'));
  });

  it('Builds JSON with the same schema, order and totals', () => {
    const parsed = JSON.parse(buildJsonPostMortem(cluster)) as {
      schema: string;
      alerts: Array<{ id: string }>;
      valueAtRisk: Record<string, number>;
    };

    expect(parsed.schema).toBe('stellar-alerts/incident-postmortem/v1');
    expect(parsed.alerts.map((entry) => entry.id)).toEqual(['1', '2']);
    expect(parsed.valueAtRisk).toEqual({ XLM: 100 });
  });
});
