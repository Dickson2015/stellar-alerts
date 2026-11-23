# Stellar Alerts Webhook Signature Verification SDK (Python)

Minimal Python SDK for verifying Stellar Alerts webhook signatures with HMAC-SHA256, timestamp drift, and replay nonce protection.

## Installation

```bash
pip install stellar-alerts-webhook
```

## Usage

```python
from stellar_alerts_webhook import WebhookVerifier

verifier = WebhookVerifier(
    secret="your_webhook_secret",
    tolerance_ms=300000  # 5 minutes default
)

# Verify webhook signature
result = verifier.verify(
    payload=b'{"event": "payment.received"}',
    signature_header="t=1234567890,v1=abc123...",
    nonce="unique_nonce_value"
)

if result.valid:
    print("Signature valid")
else:
    print(f"Invalid signature: {result.error}")
```

## Decrypting end-to-end encrypted payloads (#929)

Subscribers that opt into encrypted delivery receive an ECIES envelope instead
of a plaintext JSON body. The ephemeral public key is in the
`Stellar-Alerts-Ephemeral-Key` header; decrypt with the account key that was
registered for the webhook:

```python
from stellar_alerts_webhook import EciesDecryptor

# Stellar S... seed, x25519:<base64|hex>, or a raw 32-byte base64 key.
decryptor = EciesDecryptor("S...")
plaintext = decryptor.decrypt_webhook(body, headers["Stellar-Alerts-Ephemeral-Key"])
```

The decryptor also verifies that the header key matches the envelope, and
rejects tampered ciphertext, tags and envelopes. Requires `cryptography>=42`.

## Features

- HMAC-SHA256 signature verification
- Timestamp drift protection (configurable tolerance)
- Replay attack prevention via nonce checking
- Grace period for key rotation (48 hours)
- ECIES (X25519 + HKDF-SHA256 + AES-256-GCM) payload decryption
