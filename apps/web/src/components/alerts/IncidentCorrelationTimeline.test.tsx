import { fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { IncidentCorrelationTimeline } from './IncidentCorrelationTimeline';

class CapturedBlob {
  constructor(
    readonly parts: string[],
    readonly options?: { type?: string },
  ) {}
}

const createObjectURL = vi.fn(() => 'blob:test');
const revokeObjectURL = vi.fn();

const alerts = [
  {
    id: 'signer-change',
    title: 'Signer changed',
    severity: 'warning',
    txHash: 'tx-attack',
    walletId: 'wallet-1',
    fromAddress: 'GATTACKER',
    amount: 10,
    asset: 'XLM',
    timestamp: '2026-11-24T10:00:00.000Z',
  },
  {
    id: 'large-outflow',
    title: 'Large outflow',
    severity: 'critical',
    txHash: 'tx-attack',
    walletId: 'wallet-1',
    fromAddress: 'GATTACKER',
    amount: 90,
    asset: 'XLM',
    timestamp: '2026-11-24T10:02:00.000Z',
  },
];

describe('IncidentCorrelationTimeline (#1044)', () => {
  beforeEach(() => {
    vi.stubGlobal('Blob', CapturedBlob);
    vi.stubGlobal('URL', { createObjectURL, revokeObjectURL });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('shows an empty state when no alerts correlate', () => {
    render(<IncidentCorrelationTimeline alerts={[]} />);
    expect(screen.getByText(/No correlated incidents/)).toBeTruthy();
  });

  it('clusters alerts and expands a chronological swimlane timeline', () => {
    render(<IncidentCorrelationTimeline alerts={alerts} />);

    const toggle = screen.getByRole('button', { name: /INC-/ });
    expect(within(toggle).getByText('2 alerts')).toBeTruthy();
    expect(within(toggle).getByText('VaR: 100 XLM')).toBeTruthy();
    expect(toggle.getAttribute('aria-expanded')).toBe('false');

    fireEvent.click(toggle);

    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    expect(screen.getByText('Signer changed')).toBeTruthy();
    expect(screen.getByText('Large outflow')).toBeTruthy();
    expect(screen.getByText(/Swimlane: wallet-1/)).toBeTruthy();
    expect(screen.getByRole('button', { name: /Export .* as Markdown/ })).toBeTruthy();
    expect(screen.getByRole('button', { name: /Export .* as JSON/ })).toBeTruthy();
  });

  it('exports Markdown and JSON post-mortems as self-contained downloads', () => {
    render(<IncidentCorrelationTimeline alerts={alerts} />);
    fireEvent.click(screen.getByRole('button', { name: /INC-/ }));

    fireEvent.click(screen.getByRole('button', { name: /Export .* as Markdown/ }));
    const markdown = createObjectURL.mock.calls[0][0] as unknown as CapturedBlob;
    expect(markdown.options?.type).toBe('text/markdown;charset=utf-8');
    expect(markdown.parts[0]).toContain('# Incident post-mortem:');
    expect(markdown.parts[0]).toContain('Signer changed');

    fireEvent.click(screen.getByRole('button', { name: /Export .* as JSON/ }));
    const json = createObjectURL.mock.calls[1][0] as unknown as CapturedBlob;
    expect(json.options?.type).toBe('application/json;charset=utf-8');
    expect(JSON.parse(json.parts[0]).alerts).toHaveLength(2);
    expect(revokeObjectURL).toHaveBeenCalledTimes(2);
  });

  it('changes the correlation window from the UI', () => {
    render(<IncidentCorrelationTimeline alerts={alerts} defaultWindowMinutes={1} />);

    const oneMinute = screen.getByRole('button', { name: '1m' });
    expect(oneMinute.getAttribute('aria-pressed')).toBe('true');
    fireEvent.click(screen.getByRole('button', { name: '5m' }));
    expect(screen.getByRole('button', { name: '5m' }).getAttribute('aria-pressed')).toBe('true');
  });
});
