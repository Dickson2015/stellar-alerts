'use client';

import { useCallback } from 'react';
import NetworkVisualizer3D from '@/components/dashboard/NetworkVisualizer3D';
import AuditWorkspace from '@/components/dashboard/AuditWorkspace';
import { useSession } from 'next-auth/react';
import type { PathPaymentFlow } from '@/components/dashboard';
import { WatcherForm } from '@/components/WatcherForm';
import {
  DashboardGrid,
  DashboardHeader,
  DeliveryToast,
  SummaryStats,
  VolumeChart,
  WebhookSandbox,
  WalletList,
  EmptyWatchersState,
  PaymentTable,
  ActivityHeatmap,
  EmailTemplatePreview,
  SankeyFlowDiagram,
} from '@/components/dashboard';
import { FilterChips } from '@/components/alerts/FilterChips';
import { useDashboardData } from '@/hooks/useDashboardData';
import { useLiveDashboardStream } from '@/hooks/useLiveDashboardStream';
import { useEmailTemplatePreference } from '@/hooks/useEmailTemplatePreference';
import { useTagFilters } from '@/hooks/useTagFilters';
import { CurrencyPreferenceProvider } from '@/components/dashboard/CurrencyPreference';

// Multi-hop path payment routes. The ingestion worker does not yet record
// path_payment_* offer chains, so this stays empty until a path-flows feed
// is available; the Sankey card renders its own empty state meanwhile.
const PATH_PAYMENT_FLOWS: PathPaymentFlow[] = [];

export default function DashboardPage() {
  const { data: session } = useSession();
  const {
    wallets,
    payments,
    selectedWalletId,
    setSelectedWalletId,
    isLoadingPayments,
    hasLoadedPortfolio,
    totalPaymentsCount,
    totalVolumeXLM,
    applyLivePayment,
    refreshAfterMutation,
    updateWalletMetadata,
    removeWallet,
  } = useDashboardData();
  const { isStreamConnected, latestDelivery } = useLiveDashboardStream(
    session?.accessToken,
    selectedWalletId,
    applyLivePayment,
  );
  const {
    template: savedEmailTemplate,
    saveTemplate: saveEmailTemplate,
  } = useEmailTemplatePreference(session?.accessToken);

  const { selectedTags, filterTags, visiblePayments, toggleTag, clearTags } = useTagFilters(
    wallets,
    payments,
  );

  // The Add Wallet flow is the watcher form below the grid, not a modal, so
  // "open it" means scroll it into view and put the cursor in its first field.
  const openAddWalletForm = useCallback(() => {
    const section = document.getElementById('add-wallet-section');
    if (!section) return;
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    section.querySelector<HTMLInputElement>('#address')?.focus({ preventScroll: true });
  }, []);

  return (
    <CurrencyPreferenceProvider>
    <div className="min-w-0 space-y-8">
      <DeliveryToast delivery={latestDelivery} />

      <DashboardHeader />

      {/* Onboarding card: renders only while the user has no wallets. */}
      {hasLoadedPortfolio && (
        <EmptyWatchersState walletCount={wallets.length} onAddWallet={openAddWalletForm} />
      )}

      {filterTags.length > 0 ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-semibold text-slate-200">Filter by wallet tag</h2>
            <span className="text-xs text-slate-400">
              {visiblePayments.length} matching {visiblePayments.length === 1 ? 'alert' : 'alerts'}
            </span>
          </div>
          <FilterChips
            tags={filterTags}
            selectedTags={selectedTags}
            onToggle={toggleTag}
            onClear={clearTags}
          />
        </div>
      ) : null}

      {/* Customizable Dashboard Grid */}
      <DashboardGrid
        items={[
          {
            id: 'summary',
            label: 'Summary Overview',
            content: (
              <SummaryStats
                totalPaymentsCount={totalPaymentsCount}
                totalVolumeXLM={totalVolumeXLM}
                activeWalletsCount={wallets.length}
              />
            ),
          },
          {
            id: 'volume-chart',
            label: 'Currency Volume',
            content: (
              <VolumeChart
                payments={visiblePayments}
                totalVolumeXLM={totalVolumeXLM}
              />
            ),
          },
          {
            id: 'activity-heatmap',
            label: 'Activity Heatmap',
            content: <ActivityHeatmap payments={visiblePayments} />,
          },
          {
            id: 'email-template-preview',
            label: 'Email Receipt Template',
            content: (
              <EmailTemplatePreview
                initialTemplate={savedEmailTemplate ?? undefined}
                onSaveTemplate={saveEmailTemplate}
              />
            ),
          },
          {
            id: 'webhook-sandbox',
            label: 'Webhook Sandbox',
            content: <WebhookSandbox />,
          },
          // Hidden at zero wallets: the onboarding card above already explains
          // the empty table, so showing both would be two competing CTAs.
          ...(wallets.length > 0
            ? [
                {
                  id: 'wallets',
                  label: 'Monitored Wallets',
                  content: (
                    <WalletList
                      wallets={wallets}
                      selectedWalletId={selectedWalletId}
                      onSelectWallet={setSelectedWalletId}
                      onRemoveWallet={removeWallet}
                      onOpenAddModal={openAddWalletForm}
                      onUpdateWalletMetadata={updateWalletMetadata}
                    />
                  ),
                },
              ]
            : []),
          {
            id: 'watcher-and-payments',
            label: 'Watcher & Payment Ledger',
            content: (
              <div id="add-wallet-section" className="min-w-0 grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
                <div className="min-w-0 lg:col-span-4 bg-[#0c0c14]/80 backdrop-blur-md rounded-3xl border border-white/10 p-7 shadow-2xl hover:border-cyan-500/30 transition-all duration-500">
                  <WatcherForm onWalletAdded={refreshAfterMutation} isStreamConnected={isStreamConnected} />
                </div>
                <div className="min-w-0 lg:col-span-8">
                  <PaymentTable
                    payments={visiblePayments}
                    isLoading={isLoadingPayments}
                    hasExternalFilters={selectedTags.length > 0}
                    onClearFilters={clearTags}
                  />
                </div>
              </div>
            ),
          },
          {
            id: 'network-visualizer',
            label: 'Live Payment Stream Network',
            content: <NetworkVisualizer3D payments={visiblePayments} />,
          },
          {
            id: 'audit-workspace',
            label: 'Collaborative Audit Workspace',
            content: (
              <AuditWorkspace
                payments={payments}
                currentUser={{
                  id: session?.user?.id || session?.user?.email || 'anonymous',
                  name: session?.user?.name || session?.user?.email || 'Auditor',
                }}
              />
            ),
          },
          {
            id: 'sankey-flows',
            label: 'Multi-Hop Payment Flows',
            content: <SankeyFlowDiagram flows={PATH_PAYMENT_FLOWS} />,
          },
        ]}
      />
    </div>
    </CurrencyPreferenceProvider>
  );
}
