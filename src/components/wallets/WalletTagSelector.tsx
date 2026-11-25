import { useMemo } from "react";

export interface WalletTagSelectorProps {
  availableTags: string[];
  selectedTags: Set<string>;
  onChange: (tags: string[]) => void;
  disabled?: boolean;
}

export function WalletTagSelector({
  availableTags,
  selectedTags,
  onChange,
  disabled = false,
}: WalletTagSelectorProps) {
  const sortedTags = useMemo(
    () => [...availableTags].sort((a, b) => a.localeCompare(b)),
    [availableTags],
  );

  const toggleTag = (tag: string) => {
    const next = new Set<string>(selectedTags);
    if (next.has(tag)) {
      next.delete(tag);
    } else {
      next.add(tag);
    }
    onChange(Array.from(next));
  };

  return (
    <div role="group" aria-label="Wallet tags" className="flex flex-wrap gap-2">
      {sortedTags.map((tag: string) => {
        const checked = selectedTags.has(tag);
        return (
          <label
            key={tag}
            className={`inline-flex items-center gap-1 rounded px-2 py-1 text-sm border ${
              checked ? "bg-blue-100 border-blue-400" : "border-gray-300"
            }`}
          >
            <input
              type="checkbox"
              className="sr-only"
              checked={checked}
              disabled={disabled}
              onChange={() => toggleTag(tag)}
            />
            <span>{tag}</span>
          </label>
        );
      })}
    </div>
  );
}

export default WalletTagSelector;
