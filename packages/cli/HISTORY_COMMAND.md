# History Command

## Overview
The `history` command displays alert/payment history from the Stellar Alerts system with support for both human-readable table output and machine-parseable JSON format.

## Usage

```bash
stellar-alerts history [options]
```

## Options

- `-w, --wallet-id <walletId>` - Filter history by specific wallet ID
- `-l, --limit <limit>` - Limit number of results (default: 50)
- `-f, --format <format>` - Output format: `json` or `table` (default: `table`)
- `-t, --token <token>` - API authentication token (overrides profile)

## Examples

### View history as formatted table (default)
```bash
stellar-alerts history
```

### View history as JSON
```bash
stellar-alerts history --format json
```

### Filter by wallet with limited results
```bash
stellar-alerts history --wallet-id wallet-123 --limit 10
```

### Pipe JSON output to jq for processing
```bash
stellar-alerts history --format json | jq '.[] | select(.amount > 100)'
```

### Use in CI/CD scripts
```bash
# Check if any payments received in last 24 hours
PAYMENTS=$(stellar-alerts history --format json --limit 100)
COUNT=$(echo $PAYMENTS | jq 'length')
echo "Received $COUNT payments"
```

## Output Formats

### Table Format
Human-readable ANSI-formatted table with colored output:
```
📜 Payment History (3 records)

────────────────────────────────────────────────────────────────────
ID                          From                      Amount    Asset  Date
────────────────────────────────────────────────────────────────────
payment-1                   GABC123...                100.00    XLM    1/1/2024, 12:00:00 AM
payment-2                   GDEF456...                50.50     USD    1/2/2024, 3:30:00 PM
payment-3                   GHIJ789...                200.00    XLM    1/3/2024, 9:15:00 AM
────────────────────────────────────────────────────────────────────
```

### JSON Format
Structured JSON array suitable for parsing:
```json
[
  {
    "id": "payment-1",
    "walletId": "wallet-1",
    "txHash": "hash-1",
    "fromAddress": "GABC123...",
    "amount": "100.00",
    "asset": "XLM",
    "memo": null,
    "receivedAt": "2024-01-01T00:00:00Z",
    "pagingToken": "token-1"
  }
]
```

## Error Handling

- Invalid format option returns exit code 1 with helpful message
- Network errors are caught and displayed with appropriate error code
- Authentication failures show clear error messages

## Testing

Run the test suite:
```bash
npm test -- history.test.ts
npm test -- formatters.test.ts
```

## Implementation Details

- Uses existing `ApiClient.getPayments()` method
- Formatters are separated into `utils/formatters.ts` for reusability
- Follows Commander.js patterns used in other commands
- Maintains backward compatibility (table is default format)
