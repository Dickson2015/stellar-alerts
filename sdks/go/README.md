# Stellar Alerts Webhook Signature Verification SDK (Go)

Minimal Go SDK for verifying Stellar Alerts webhook signatures with HMAC-SHA256, timestamp drift, and replay nonce protection.

## Installation

```bash
go get github.com/stellar-alerts-labs/stellar-alerts/sdks/go
```

## Usage

```go
package main

import (
    "fmt"
    "github.com/stellar-alerts-labs/stellar-alerts/sdks/go"
)

func main() {
    verifier := webhook.NewVerifier("your_webhook_secret", 300000) // 5 minutes tolerance
    
    result := verifier.Verify(
        []byte(`{"event": "payment.received"}`),
        "t=1234567890,v1=abc123...",
        "unique_nonce_value",
    )
    
    if result.Valid {
        fmt.Println("Signature valid")
    } else {
        fmt.Printf("Invalid signature: %s\n", result.Error)
    }
}
```

## Decrypting end-to-end encrypted payloads (#929)

When a webhook is configured for encrypted delivery the body is an ECIES
envelope and the ephemeral public key is published in the
`Stellar-Alerts-Ephemeral-Key` header:

```go
decryptor, err := webhook.NewEciesDecryptor(os.Getenv("WEBHOOK_PRIVATE_KEY"))
if err != nil {
    log.Fatal(err)
}
plaintext, err := decryptor.DecryptWebhook(
    body,
    r.Header.Get(webhook.EphemeralKeyHeader),
)
```

Private keys may be a Stellar `S...` seed, `x25519:<base64|hex>`, or a raw
32-byte key. The header is checked against the envelope so a proxy cannot
swap either half of the delivery.

## Features

- HMAC-SHA256 signature verification
- Timestamp drift protection (configurable tolerance)
- Replay attack prevention via nonce checking
- Grace period for key rotation (48 hours)
- ECIES (X25519 + HKDF-SHA256 + AES-256-GCM) payload decryption
