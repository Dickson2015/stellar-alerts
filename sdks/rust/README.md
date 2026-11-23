# Stellar Alerts Webhook Signature Verification SDK (Rust)

Rust SDK for verifying Stellar Alerts webhook signatures (HMAC-SHA256 or
Ed25519), timestamp drift tolerance, replay-nonce protection, and typed
deserialization of the alert payload itself.

## Installation

Add to `Cargo.toml`:

```toml
[dependencies]
stellar-alerts-webhook = "0.2.0"
```

## Verifying a signature

The signature header format is `t=<unix_ms>[,n=<nonce>],v1=<hex_hmac>` for
HMAC-signed webhooks, or `...,v2=<hex_ed25519_signature>` for Ed25519-signed
webhooks — matching `apps/api/src/utils/webhook-signer.ts` exactly.

### HMAC-SHA256 (default)

```rust
use stellar_alerts_webhook::WebhookVerifier;

let verifier = WebhookVerifier::new_hmac("your_webhook_secret", 300_000); // 5 minute tolerance

let result = verifier.verify(
    br#"{"event":"payment.received","payment_id":"pay_1", ...}"#,
    "t=1732000000000,n=unique-nonce,v1=abc123...",
);

if result.is_valid() {
    println!("Signature valid");
} else {
    println!("Invalid signature: {}", result.error().unwrap_or("unknown"));
}
```

### Ed25519

```rust
use stellar_alerts_webhook::WebhookVerifier;

let public_key: [u8; 32] = /* your configured public key */;
let verifier = WebhookVerifier::new_ed25519(&public_key, 300_000)?;

let result = verifier.verify(payload_bytes, "t=1732000000000,v2=abc123...");
```

Signature comparison is constant-time for both schemes (HMAC via
`subtle::ConstantTimeEq` over the raw bytes; Ed25519 via
`ed25519-dalek`'s own constant-time verification), so a timing side-channel
can't be used to brute-force a valid signature byte by byte.

Each `WebhookVerifier` instance tracks nonces it has already seen in
memory and rejects a repeat — construct one verifier per process/secret and
reuse it across requests, rather than creating a new one per call, or
replay protection has no effect.

## Deserializing the alert payload

```rust
use stellar_alerts_webhook::StellarAlertEvent;

let event: StellarAlertEvent = serde_json::from_str(json_body)?;

match event {
    StellarAlertEvent::PaymentReceived(alert) | StellarAlertEvent::PaymentAlert(alert) => {
        println!("Payment {} for {} {}", alert.payment_id, alert.amount, alert.asset);
    }
    StellarAlertEvent::SorobanContractEvent(evt) => {
        println!("Contract {} emitted on ledger {}", evt.contract_id, evt.ledger);
    }
}
```

`StellarAlertEvent` is discriminated by the payload's `event` field. Note
that a webhook's payload shape can be customized via a Handlebars template
on the Stellar Alerts dashboard; `StellarAlertEvent` models the *default*
(non-templated) payload shape delivered when no custom template is set.

## Decrypting end-to-end encrypted payloads (#929)

```rust
use stellar_alerts_webhook::EciesDecryptor;

let decryptor = EciesDecryptor::new(&std::env::var("WEBHOOK_PRIVATE_KEY")?)?;
let plaintext = decryptor.decrypt_webhook(&body, Some(&ephemeral_key_header))?;
```

The body is a JSON ECIES envelope (`v`, `alg`, `curve`, `epk`, `iv`, `ct`,
`tag`); the ephemeral key is mirrored in `Stellar-Alerts-Ephemeral-Key` and
verified against the envelope. Private keys may be a Stellar `S...` seed,
`x25519:`/`ed25519:` prefixed keys, or a raw 32-byte hex/base64 key.

## Features

- HMAC-SHA256 or Ed25519 signature verification, both constant-time
- Timestamp drift protection (configurable tolerance)
- Replay attack prevention via in-memory nonce tracking
- Strongly-typed `PaymentAlert` / `SorobanEvent` payload models
- ECIES (X25519 + HKDF-SHA256 + AES-256-GCM) payload decryption
