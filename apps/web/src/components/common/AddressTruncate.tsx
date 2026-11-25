export interface AddressTruncateProps {
  value: string;
  prefixChars?: number;
  suffixChars?: number;
  className?: string;
}

const ELLIPSIS = '...';

function normalizeCount(count: number): number {
  if (!Number.isFinite(count)) return 0;
  return Math.max(0, Math.floor(count));
}

export function truncateMiddle(value: string, prefixChars = 6, suffixChars = 6): string {
  const prefix = normalizeCount(prefixChars);
  const suffix = normalizeCount(suffixChars);

  if (value.length <= prefix + suffix + ELLIPSIS.length) {
    return value;
  }

  return `${value.slice(0, prefix)}${ELLIPSIS}${value.slice(value.length - suffix)}`;
}

export function AddressTruncate({ value, prefixChars = 6, suffixChars = 6, className }: AddressTruncateProps) {
  return (
    <span className={className} title={value} aria-label={value}>
      {truncateMiddle(value, prefixChars, suffixChars)}
    </span>
  );
}

export default AddressTruncate;
