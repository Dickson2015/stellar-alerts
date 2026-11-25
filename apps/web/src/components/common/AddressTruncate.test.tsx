import React from 'react';
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { AddressTruncate } from './AddressTruncate';

const G_ADDRESS = 'GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI';
const C_ADDRESS = 'CCBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMAD';

describe('AddressTruncate', () => {
  it('truncates a 56-character G address with the default prefix and suffix lengths', () => {
    render(<AddressTruncate value={G_ADDRESS} />);

    const truncated = screen.getByText('GBZXN7...DNMADI');
    expect(truncated).toBeInTheDocument();
    expect(truncated).toHaveAttribute('title', G_ADDRESS);
    expect(truncated).toHaveAttribute('aria-label', G_ADDRESS);
  });

  it('truncates a 56-character C address with configurable prefix and suffix lengths', () => {
    render(<AddressTruncate value={C_ADDRESS} prefixChars={6} suffixChars={6} />);

    const truncated = screen.getByText('CCBZXN...FDNMAD');
    expect(truncated).toBeInTheDocument();
    expect(truncated).toHaveAttribute('title', C_ADDRESS);
    expect(truncated).toHaveAttribute('aria-label', C_ADDRESS);
  });

  it('honors shorter custom prefix and suffix lengths', () => {
    render(<AddressTruncate value={G_ADDRESS} prefixChars={4} suffixChars={4} />);

    expect(screen.getByText('GBZX...MADI')).toBeInTheDocument();
  });

  it('does not truncate short strings', () => {
    render(<AddressTruncate value="short" />);

    const value = screen.getByText('short');
    expect(value).toBeInTheDocument();
    expect(value).toHaveAttribute('title', 'short');
    expect(value).toHaveAttribute('aria-label', 'short');
  });

  it('keeps the full transaction hash on the element for assistive technology', () => {
    const hash = 'a'.repeat(64);
    render(<AddressTruncate value={hash} prefixChars={8} suffixChars={8} />);

    const truncated = screen.getByText('aaaaaaaa...aaaaaaaa');
    expect(truncated).toHaveAttribute('aria-label', hash);
    expect(truncated.getAttribute('aria-label')).toContain(hash);
    expect(truncated).toHaveAttribute('title', hash);
  });
});
