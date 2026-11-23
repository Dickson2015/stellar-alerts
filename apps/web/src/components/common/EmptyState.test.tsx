import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { EmptyState } from './EmptyState';

describe('EmptyState', () => {
  it('renders the heading, subtitle and a decorative SVG illustration', () => {
    render(<EmptyState title="Nothing here" description="Try again later." />);

    const status = screen.getByRole('status', { name: 'Nothing here' });
    expect(status).toHaveAccessibleDescription('Try again later.');
    expect(screen.getByRole('heading', { name: 'Nothing here' })).toBeInTheDocument();
    expect(screen.getByTestId('empty-state-illustration')).toHaveAttribute('aria-hidden', 'true');
  });

  it.each(['no-results', 'no-wallets', 'no-data'] as const)('renders the %s variant', (variant) => {
    render(<EmptyState title="Empty" variant={variant} />);

    expect(screen.getByTestId('empty-state')).toHaveAttribute('data-variant', variant);
    expect(screen.getByTestId('empty-state-illustration').childElementCount).toBeGreaterThan(0);
  });

  it('invokes the filter reset handler when the CTA is clicked', () => {
    const onReset = vi.fn();
    render(
      <EmptyState
        title="No matches"
        variant="no-results"
        action={{ label: 'Clear all filters', onClick: onReset }}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Clear all filters' }));

    expect(onReset).toHaveBeenCalledTimes(1);
  });

  it('renders no button and no description when they are omitted', () => {
    render(<EmptyState title="Empty" />);

    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(screen.getByRole('status')).not.toHaveAttribute('aria-describedby');
  });
});
