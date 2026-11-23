//! Rust SDK for verifying Stellar Alerts webhook signatures and
//! deserializing their typed alert payloads.
//!
//! See [`WebhookVerifier`] for signature verification (HMAC-SHA256 or
//! Ed25519, timestamp drift tolerance, nonce-based anti-replay),
//! [`EciesDecryptor`] for end-to-end encrypted payload delivery, and
//! [`StellarAlertEvent`] for the strongly-typed payload shapes.

mod ecies;
mod events;
mod verifier;

pub use ecies::{
    EciesDecryptor, EciesDecryptionError, EciesEnvelope, ECIES_ALGORITHM, ECIES_CURVE,
    ECIES_VERSION, ENCRYPTION_HEADER, EPHEMERAL_KEY_HEADER,
};
pub use events::{PaymentAlert, SorobanEvent, StellarAlertEvent};
pub use verifier::{VerificationResult, WebhookVerifier, DEFAULT_TOLERANCE_MS};
