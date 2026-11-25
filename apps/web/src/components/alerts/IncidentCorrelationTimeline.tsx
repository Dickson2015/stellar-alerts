'use client';

import { useMemo, useState } from 'react';
import {
  buildJsonPostMortem,
  buildMarkdownPostMortem,
  clusterAlerts,
  normalizeAlerts,
  type CorrelatableAlert,
  type IncidentCluster,
  type NormalizableAlert,
} from '@/utils/alert-correlator';

export interface IncidentCorrelationTimelineProps {
  alerts: readonly NormalizableAlert[];
  /** Minutes in the clustering window; users can override it in the UI. */
  defaultWindowMinutes?: number;
}

const WINDOW_CHOICES = [1, 5, 15, 60];

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
  warning: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  info: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40',
};

function download(filename: string, contents: string, mimeType: string): void {
  const blob = new Blob([contents], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function laneFor(alert: CorrelatableAlert): string {
  return alert.walletId ?? alert.counterparties[0] ?? alert.txHash ?? 'Shared context';
}

function IncidentNode({ alert }: { alert: CorrelatableAlert }) {
  return (
    <li className="relative pl-7 pb-5 last:pb-0 before:absolute before:left-[7px] before:top-2 before:h-full before:w-px before:bg-slate-700 last:before:hidden">
      <span
        aria-hidden="true"
        className={`absolute left-0 top-2 h-3.5 w-3.5 rounded-full border ${SEVERITY_STYLES[alert.severity]}`}
      />
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <time className="font-mono text-[11px] text-slate-400" dateTime={alert.timestamp}>
          {new Date(alert.timestamp).toLocaleString()}
        </time>
        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase ${SEVERITY_STYLES[alert.severity]}`}>
          {alert.severity}
        </span>
        <span className="text-sm font-medium text-slate-100">{alert.title}</span>
      </div>
      <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-slate-400">
        <span>ID: {alert.id}</span>
        {alert.txHash ? <span className="font-mono">tx: {alert.txHash}</span> : null}
        {alert.counterparties.length > 0 ? <span>counterparty: {alert.counterparties[0]}</span> : null}
        {alert.amount !== undefined ? <span>{alert.amount} {alert.asset ?? 'UNKNOWN'}</span> : null}
      </div>
    </li>
  );
}

function IncidentCard({ cluster }: { cluster: IncidentCluster }) {
  const lanes = useMemo(() => {
    const grouped = new Map<string, CorrelatableAlert[]>();
    for (const alert of cluster.alerts) {
      const lane = laneFor(alert);
      grouped.set(lane, [...(grouped.get(lane) ?? []), alert]);
    }
    return [...grouped.entries()];
  }, [cluster]);

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm font-semibold text-cyan-300">{cluster.id}</span>
            <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase ${SEVERITY_STYLES[cluster.severity]}`}>
              {cluster.severity}
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            {new Date(cluster.startedAt).toLocaleString()} — {cluster.alerts.length} correlated alert
            {cluster.alerts.length === 1 ? '' : 's'}
          </p>
        </div>
        <div className="text-right text-xs">
          <span className="block text-slate-500">Value at risk</span>
          <span className="font-semibold text-slate-200">{cluster.valueAtRiskLabel}</span>
        </div>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        {lanes.map(([lane, alerts]) => (
          <div key={lane} className="rounded-lg border border-white/5 bg-[#0b0c16] p-3">
            <p className="mb-3 truncate text-[11px] font-medium uppercase tracking-wide text-slate-500">
              Swimlane: {lane}
            </p>
            <ol className="m-0 list-none p-0">
              {alerts.map((alert) => <IncidentNode key={alert.id} alert={alert} />)}
            </ol>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Groups correlated security alerts into an expandable chronological timeline
 * and exports the whole incident as a self-contained Markdown or JSON report.
 */
export function IncidentCorrelationTimeline({
  alerts,
  defaultWindowMinutes = 5,
}: IncidentCorrelationTimelineProps) {
  const [windowMinutes, setWindowMinutes] = useState(defaultWindowMinutes);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const clusters = useMemo(
    () => clusterAlerts(normalizeAlerts(alerts), { windowMs: windowMinutes * 60_000 }),
    [alerts, windowMinutes],
  );

  return (
    <section
      aria-label="Incident correlation timeline"
      className="min-w-0 rounded-2xl border border-white/10 bg-[#0c0c14]/80 p-5 shadow-xl backdrop-blur-md"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-slate-100">Incident correlation timeline</h2>
          <p className="text-xs text-slate-400">
            Correlates alerts sharing a wallet, transaction or counterparty into one attack story.
          </p>
        </div>
        <div className="flex items-center gap-1" role="group" aria-label="Correlation window">
          {WINDOW_CHOICES.map((minutes) => (
            <button
              key={minutes}
              type="button"
              onClick={() => setWindowMinutes(minutes)}
              aria-pressed={windowMinutes === minutes}
              className={`rounded-md border px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-cyan-500 ${
                windowMinutes === minutes
                  ? 'border-cyan-500/50 bg-cyan-500/15 text-cyan-200'
                  : 'border-slate-700 text-slate-400 hover:text-slate-200'
              }`}
            >
              {minutes}m
            </button>
          ))}
        </div>
      </div>

      {clusters.length === 0 ? (
        <p className="mt-6 rounded-lg border border-dashed border-slate-700 p-6 text-center text-sm text-slate-500">
          No correlated incidents in this window. Add alerts sharing a wallet, transaction or counterparty.
        </p>
      ) : (
        <ol className="mt-5 space-y-3">
          {clusters.map((cluster) => (
            <li key={cluster.id}>
              <button
                type="button"
                aria-expanded={expandedId === cluster.id}
                onClick={() => setExpandedId((current) => current === cluster.id ? null : cluster.id)}
                className="flex w-full flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-4 py-3 text-left transition-colors hover:border-cyan-500/40 focus:outline-none focus:ring-2 focus:ring-cyan-500"
              >
                <span className="font-mono text-sm text-cyan-300">{cluster.id}</span>
                <span className="flex flex-wrap items-center gap-3 text-xs text-slate-400">
                  <span>{cluster.alerts.length} alerts</span>
                  <span>VaR: {cluster.valueAtRiskLabel}</span>
                  <span aria-hidden="true">{expandedId === cluster.id ? '▾' : '▸'}</span>
                </span>
              </button>
              {expandedId === cluster.id ? (
                <div className="mt-3 space-y-3">
                  <IncidentCard cluster={cluster} />
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      aria-label={`Export ${cluster.id} as Markdown`}
                      onClick={() => download(
                        `${cluster.id}.md`,
                        buildMarkdownPostMortem(cluster),
                        'text/markdown;charset=utf-8',
                      )}
                      className="rounded-md border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:border-cyan-500/40 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    >
                      Export Markdown
                    </button>
                    <button
                      type="button"
                      aria-label={`Export ${cluster.id} as JSON`}
                      onClick={() => download(
                        `${cluster.id}.json`,
                        buildJsonPostMortem(cluster),
                        'application/json;charset=utf-8',
                      )}
                      className="rounded-md border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:border-cyan-500/40 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    >
                      Export JSON
                    </button>
                  </div>
                </div>
              ) : null}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

export default IncidentCorrelationTimeline;
