import React, { useId } from 'react';

export type EmptyStateVariant = 'no-results' | 'no-wallets' | 'no-data';

export interface EmptyStateAction {
  label: string;
  onClick: () => void;
}

export interface EmptyStateProps {
  title: string;
  description?: string;
  variant?: EmptyStateVariant;
  action?: EmptyStateAction;
  className?: string;
  testId?: string;
}

export function EmptyState({
  title,
  description,
  variant = 'no-data',
  action,
  className = '',
  testId = 'empty-state',
}: EmptyStateProps) {
  const id = useId();
  const titleId = `${id}-title`;
  const descriptionId = `${id}-description`;

  return (
    <div
      role="status"
      aria-labelledby={titleId}
      aria-describedby={description ? descriptionId : undefined}
      data-testid={testId}
      data-variant={variant}
      className={`flex flex-col items-center gap-3 rounded-xl border border-slate-800/80 bg-slate-950/40 p-10 text-center ${className}`}
    >
      <EmptyStateIllustration variant={variant} />
      <h3 id={titleId} className="text-sm font-semibold text-slate-200">
        {title}
      </h3>
      {description ? (
        <p id={descriptionId} className="max-w-sm text-xs text-slate-400">
          {description}
        </p>
      ) : null}
      {action ? (
        <button
          type="button"
          onClick={action.onClick}
          data-testid={`${testId}-action`}
          className="mt-2 inline-flex items-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-xs font-semibold text-cyan-400 transition-colors hover:bg-cyan-500/20 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/70 cursor-pointer"
        >
          {action.label}
        </button>
      ) : null}
    </div>
  );
}

function EmptyStateIllustration({ variant }: { variant: EmptyStateVariant }) {
  return (
    <svg
      aria-hidden="true"
      focusable="false"
      viewBox="0 0 64 64"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      className="h-14 w-14 text-cyan-400/70"
      data-testid="empty-state-illustration"
    >
      {variant === 'no-results' ? (
        <>
          <circle cx="28" cy="28" r="16" />
          <path d="M40 40l12 12" />
          <path d="M22 22l12 12M34 22L22 34" strokeOpacity={0.6} />
        </>
      ) : variant === 'no-wallets' ? (
        <>
          <rect x="8" y="18" width="44" height="32" rx="6" />
          <path d="M8 26h44" strokeOpacity={0.6} />
          <rect x="38" y="32" width="14" height="10" rx="3" />
          <path d="M52 8v12M46 14h12" />
        </>
      ) : (
        <>
          <path d="M10 36l8-22h28l8 22" />
          <path d="M10 36v14h44V36H42l-4 6H26l-4-6H10z" />
        </>
      )}
    </svg>
  );
}

export default EmptyState;
