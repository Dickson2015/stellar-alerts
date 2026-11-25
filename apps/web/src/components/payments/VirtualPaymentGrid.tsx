'use client';

import React, { useMemo, useRef, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import type { PaymentDTO } from '@stellar-alerts/shared';
import { EmptyState } from '@/components/common/EmptyState';

export interface VirtualPaymentGridProps {
  payments: PaymentDTO[];
  /** Fixed row height in px. Required by the virtualizer; every row renders at this height. */
  rowHeight?: number;
  /** Height of the scrollable viewport in px. */
  height?: number;
}

type SortColumn = 'receivedAt' | 'amount' | 'asset' | 'fromAddress';
type SortDirection = 'asc' | 'desc';

const COLUMNS: Array<{ key: SortColumn; label: string }> = [
  { key: 'receivedAt', label: 'Timestamp' },
  { key: 'amount', label: 'Amount' },
  { key: 'asset', label: 'Asset' },
  { key: 'fromAddress', label: 'Address' },
];

const DEFAULT_ROW_HEIGHT = 44;
const DEFAULT_VIEWPORT_HEIGHT = 480;

function compareValues(a: PaymentDTO, b: PaymentDTO, column: SortColumn): number {
  switch (column) {
    case 'receivedAt':
      return new Date(a.receivedAt).getTime() - new Date(b.receivedAt).getTime();
    case 'amount':
      return Number(a.amount) - Number(b.amount);
    case 'asset':
      return a.asset.localeCompare(b.asset);
    case 'fromAddress':
      return a.fromAddress.localeCompare(b.fromAddress);
    default:
      return 0;
  }
}

/** Pure sort function, exported so it can be unit tested without mounting the virtualized DOM. */
export function sortPayments(
  payments: PaymentDTO[],
  column: SortColumn | null,
  direction: SortDirection,
): PaymentDTO[] {
  if (!column) return payments;
  const sorted = [...payments].sort((a, b) => compareValues(a, b, column));
  return direction === 'asc' ? sorted : sorted.reverse();
}

function truncateAddress(address: string): string {
  return address.length > 16 ? `${address.slice(0, 8)}...${address.slice(-6)}` : address;
}

/**
 * Renders a payment list of any size at a constant DOM-node count by only
 * mounting the rows currently in (or just outside) the scrollable viewport.
 * Unlike PaymentTable.tsx (the live-streaming dashboard view, with search/
 * export/currency conversion built in), this is meant for inspecting a
 * large, already-loaded batch of records — e.g. a treasury audit spanning
 * months of history — where rendering every row as a real DOM node would
 * make the browser tab itself the bottleneck (#939).
 */
export const VirtualPaymentGrid: React.FC<VirtualPaymentGridProps> = ({
  payments,
  rowHeight = DEFAULT_ROW_HEIGHT,
  height = DEFAULT_VIEWPORT_HEIGHT,
}) => {
  const [sortColumn, setSortColumn] = useState<SortColumn | null>(null);
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc');
  const scrollRef = useRef<HTMLDivElement>(null);

  const sortedPayments = useMemo(
    () => sortPayments(payments, sortColumn, sortDirection),
    [payments, sortColumn, sortDirection],
  );

  const virtualizer = useVirtualizer({
    count: sortedPayments.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => rowHeight,
    overscan: 10,
  });

  const handleSort = (column: SortColumn) => {
    if (sortColumn === column) {
      setSortDirection((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
  };

  const virtualItems = virtualizer.getVirtualItems();

  return (
    <div
      className="min-w-0 rounded-2xl bg-slate-900/60 border border-slate-800 backdrop-blur-xl shadow-xl overflow-hidden"
      data-testid="virtual-payment-grid"
    >
      {/* Sticky header: outside the scroll container, so it never scrolls with the rows. */}
      <div
        className="grid border-b border-slate-800 bg-slate-950/80 text-xs font-semibold uppercase tracking-wider text-slate-400"
        style={{ gridTemplateColumns: 'repeat(4, minmax(0, 1fr))' }}
        role="row"
      >
        {COLUMNS.map((col) => (
          <button
            key={col.key}
            type="button"
            onClick={() => handleSort(col.key)}
            aria-sort={sortColumn === col.key ? (sortDirection === 'asc' ? 'ascending' : 'descending') : 'none'}
            className="py-3 px-4 flex items-center gap-1.5 text-left hover:text-slate-200 transition-colors cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/70"
          >
            <span>{col.label}</span>
            {sortColumn === col.key && (
              <span aria-hidden="true" className="text-cyan-400">
                {sortDirection === 'asc' ? '▲' : '▼'}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Scrollable viewport: only this element scrolls; its height is fixed so
          the virtualizer can compute which rows are actually visible. */}
      <div
        ref={scrollRef}
        data-testid="virtual-payment-grid-viewport"
        className="overflow-auto"
        style={{ height }}
      >
        {sortedPayments.length === 0 ? (
          <EmptyState
            variant="no-data"
            title="No payments to display."
            className="m-4"
            testId="virtual-payment-grid-empty"
          />
        ) : (
          <div style={{ height: virtualizer.getTotalSize(), position: 'relative', width: '100%' }}>
            {virtualItems.map((virtualRow) => {
              const payment = sortedPayments[virtualRow.index];
              return (
                <div
                  key={payment.id}
                  data-index={virtualRow.index}
                  className="grid items-center border-b border-slate-800/60 text-sm text-slate-300 hover:bg-slate-800/30 transition-colors absolute top-0 left-0 w-full"
                  style={{
                    gridTemplateColumns: 'repeat(4, minmax(0, 1fr))',
                    height: virtualRow.size,
                    transform: `translateY(${virtualRow.start}px)`,
                  }}
                  role="row"
                >
                  <div className="py-2 px-4 text-xs font-mono text-slate-400 whitespace-nowrap overflow-hidden text-ellipsis">
                    {new Date(payment.receivedAt).toLocaleString()}
                  </div>
                  <div className="py-2 px-4 font-semibold text-emerald-400 whitespace-nowrap overflow-hidden text-ellipsis">
                    {Number(payment.amount).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 7 })}
                  </div>
                  <div className="py-2 px-4 whitespace-nowrap">
                    <span className="px-2 py-0.5 rounded-md text-xs font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20">
                      {payment.asset}
                    </span>
                  </div>
                  <div
                    className="py-2 px-4 font-mono text-xs text-slate-400 whitespace-nowrap overflow-hidden text-ellipsis"
                    title={payment.fromAddress}
                  >
                    {truncateAddress(payment.fromAddress)}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="py-2 px-4 text-xs text-slate-500 border-t border-slate-800" aria-live="polite">
        {sortedPayments.length.toLocaleString()} record{sortedPayments.length === 1 ? '' : 's'}
      </div>
    </div>
  );
};

export default VirtualPaymentGrid;
