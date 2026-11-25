import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { WalletList } from './WalletList';

describe('WalletList empty state', () => {
  it('shows an Add your first wallet CTA when no wallets are registered', () => {
    const onOpenAddModal = vi.fn();
    render(
      <WalletList
        wallets={[]}
        selectedWalletId={null}
        onSelectWallet={vi.fn()}
        onRemoveWallet={vi.fn()}
        onOpenAddModal={onOpenAddModal}
      />,
    );

    expect(screen.getByRole('heading', { name: 'No wallets registered yet' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Add your first wallet' }));

    expect(onOpenAddModal).toHaveBeenCalledTimes(1);
  });
});
