//! End-to-end decryption for Stellar Alerts encrypted webhook deliveries.
//!
//! The API seals payloads with ECIES (`stellar-alerts-ecies-v1`): a fresh
//! X25519 ephemeral key pair per delivery, HKDF-SHA256 key derivation from the
//! ECDH shared secret, and AES-256-GCM authenticated encryption. The ephemeral
//! public key travels in `Stellar-Alerts-Ephemeral-Key`; the body is a JSON
//! envelope with `{v, alg, curve, epk, iv, ct, tag}`.
//!
//! Private keys may be supplied as a Stellar `S...` secret seed, an
//! `x25519:`/`ed25519:` prefixed base64/hex key, or an unprefixed 32-byte key.
//! See `sdks/test-fixtures/ecies-v1-x25519.json` for a conformance vector.
//!
//! ## Example
//!
//! ```no_run
//! use stellar_alerts_webhook::EciesDecryptor;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let decryptor = EciesDecryptor::new(std::env::var("WEBHOOK_PRIVATE_KEY")?.as_str())?;
//! let body = std::fs::read_to_string("payload.json")?;
//! let plaintext = decryptor.decrypt(&body)?;
//! # Ok(())
//! # }
//! ```

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hkdf::Hkdf;
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha512};
use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};

pub const ECIES_VERSION: u8 = 1;
pub const ECIES_ALGORITHM: &str = "AES-256-GCM";
pub const ECIES_CURVE: &str = "x25519";
pub const ECIES_INFO_PREFIX: &str = "stellar-alerts-ecies-v1";
pub const ECIES_KEY_BYTES: usize = 32;
pub const ECIES_IV_BYTES: usize = 12;
pub const ECIES_TAG_BYTES: usize = 16;
pub const EPHEMERAL_KEY_HEADER: &str = "Stellar-Alerts-Ephemeral-Key";
pub const ENCRYPTION_HEADER: &str = "Stellar-Alerts-Encryption";

const ED25519_PUBLIC_KEY_VERSION: u8 = 6 << 3; // 'G'
const ED25519_SECRET_KEY_VERSION: u8 = 18 << 3; // 'S'

/// The JSON request body of an encrypted delivery.
#[derive(Debug, Clone, Deserialize)]
pub struct EciesEnvelope {
    pub v: u8,
    pub alg: String,
    pub curve: String,
    pub epk: String,
    pub iv: String,
    pub ct: String,
    pub tag: String,
}

#[derive(Debug, Clone)]
pub struct EciesDecryptionError(pub String);

impl fmt::Display for EciesDecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for EciesDecryptionError {}

fn error(message: impl Into<String>) -> EciesDecryptionError {
    EciesDecryptionError(message.into())
}

struct ParsedEnvelope {
    epk: Vec<u8>,
    iv: Vec<u8>,
    ct: Vec<u8>,
    tag: Vec<u8>,
}

fn parse_envelope(raw: &str) -> Result<ParsedEnvelope, EciesDecryptionError> {
    let envelope: EciesEnvelope =
        serde_json::from_str(raw).map_err(|_| error("Invalid ECIES envelope JSON"))?;

    if envelope.v != ECIES_VERSION
        || envelope.alg != ECIES_ALGORITHM
        || envelope.curve != ECIES_CURVE
    {
        return Err(error(
            "Unsupported ECIES envelope version, algorithm or curve",
        ));
    }

    let decode = |value: &str, field: &str| {
        BASE64
            .decode(value)
            .map_err(|_| error(format!("Envelope field '{field}' is not valid base64")))
    };

    let epk = decode(&envelope.epk, "epk")?;
    let iv = decode(&envelope.iv, "iv")?;
    let ct = decode(&envelope.ct, "ct")?;
    let tag = decode(&envelope.tag, "tag")?;

    if epk.len() != ECIES_KEY_BYTES {
        return Err(error("Invalid ephemeral public key length"));
    }
    if iv.len() != ECIES_IV_BYTES {
        return Err(error("Invalid AES-GCM nonce length"));
    }
    if tag.len() != ECIES_TAG_BYTES {
        return Err(error("Invalid AES-GCM tag length"));
    }

    Ok(ParsedEnvelope { epk, iv, ct, tag })
}

/// Decrypts `stellar-alerts-ecies-v1` envelopes for one subscriber key.
pub struct EciesDecryptor {
    private_key: [u8; ECIES_KEY_BYTES],
}

impl EciesDecryptor {
    /// Normalizes a Stellar / X25519 / Ed25519 private key into X25519 form.
    pub fn new(private_key: &str) -> Result<Self, EciesDecryptionError> {
        Ok(Self {
            private_key: resolve_x25519_private_key(private_key)?,
        })
    }

    /// Decrypts a JSON envelope and returns the UTF-8 body.
    pub fn decrypt(&self, envelope_json: &str) -> Result<String, EciesDecryptionError> {
        let parsed = parse_envelope(envelope_json)?;
        let info = format!("{ECIES_INFO_PREFIX}:{ECIES_CURVE}");

        let secret = StaticSecret::from(self.private_key);
        let ephemeral = PublicKey::from(
            <[u8; ECIES_KEY_BYTES]>::try_from(parsed.epk.as_slice())
                .map_err(|_| error("Invalid ephemeral public key"))?,
        );
        let shared = secret.diffie_hellman(&ephemeral);

        let hkdf = Hkdf::<Sha256>::new(Some(&parsed.epk), shared.as_bytes());
        let mut aes_key = [0u8; ECIES_KEY_BYTES];
        hkdf.expand(info.as_bytes(), &mut aes_key)
            .map_err(|_| error("HKDF key derivation failed"))?;

        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|_| error("AES-GCM initialization failed"))?;
        let nonce = Nonce::from_slice(&parsed.iv);

        let mut sealed = parsed.ct;
        sealed.extend_from_slice(&parsed.tag);

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &sealed,
                    aad: info.as_bytes(),
                },
            )
            .map_err(|_| error("Encrypted webhook payload failed authentication"))?;

        String::from_utf8(plaintext).map_err(|_| error("Decrypted payload is not valid UTF-8"))
    }

    /// Also verifies the `Stellar-Alerts-Ephemeral-Key` header when present.
    pub fn decrypt_webhook(
        &self,
        body: &str,
        ephemeral_key_header: Option<&str>,
    ) -> Result<String, EciesDecryptionError> {
        if let Some(header) = ephemeral_key_header {
            let parsed = parse_envelope(body)?;
            let header_bytes = BASE64
                .decode(header)
                .map_err(|_| error("Stellar-Alerts-Ephemeral-Key is not valid base64"))?;
            if header_bytes != parsed.epk {
                return Err(error(
                    "Stellar-Alerts-Ephemeral-Key does not match the envelope",
                ));
            }
        }
        self.decrypt(body)
    }
}

fn resolve_x25519_private_key(private_key: &str) -> Result<[u8; ECIES_KEY_BYTES], EciesDecryptionError> {
    let value = private_key.trim();
    if value.is_empty() {
        return Err(error("Recipient private key is required"));
    }

    if let Some(rest) = value.strip_prefix("x25519:") {
        let raw = decode_raw_key(rest)?;
        return <[u8; ECIES_KEY_BYTES]>::try_from(raw.as_slice())
            .map_err(|_| error("X25519 private key must be 32 bytes"));
    }

    if let Some(rest) = value.strip_prefix("ed25519:") {
        let seed = decode_raw_key(rest)?;
        if seed.len() != ECIES_KEY_BYTES {
            return Err(error("Ed25519 secret key must be 32 bytes"));
        }
        return Ok(ed25519_seed_to_x25519(&seed));
    }

    if value.starts_with("secp256k1:") {
        return Err(error(
            "This SDK decrypts X25519 envelopes; secp256k1 recipients must use a secp256k1 SDK",
        ));
    }

    if value.len() == 56 && (value.starts_with('S') || value.starts_with('G')) {
        let (version, payload) = decode_strkey(value)?;
        if version == ED25519_SECRET_KEY_VERSION {
            return Ok(ed25519_seed_to_x25519(&payload));
        }
        if version == ED25519_PUBLIC_KEY_VERSION {
            return Err(error(
                "Expected a Stellar secret seed (S...), got a public key",
            ));
        }
        return Err(error("Unsupported Stellar StrKey version"));
    }

    let raw = decode_raw_key(value)?;
    <[u8; ECIES_KEY_BYTES]>::try_from(raw.as_slice())
        .map_err(|_| error("Private key must be 32 bytes (base64 or hex)"))
}

fn decode_raw_key(value: &str) -> Result<Vec<u8>, EciesDecryptionError> {
    let trimmed = value.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(decoded) = hex::decode(trimmed) {
            return Ok(decoded);
        }
    }

    BASE64
        .decode(trimmed)
        .map_err(|_| error("Invalid base64/hex private key"))
}

fn ed25519_seed_to_x25519(seed: &[u8]) -> [u8; ECIES_KEY_BYTES] {
    let digest = Sha512::digest(seed);
    let mut key = [0u8; ECIES_KEY_BYTES];
    key.copy_from_slice(&digest[..ECIES_KEY_BYTES]);
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}

fn decode_strkey(value: &str) -> Result<(u8, Vec<u8>), EciesDecryptionError> {
    let decoded = data_encoding::BASE32_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| error("Invalid Stellar StrKey encoding"))?;

    if decoded.len() != 35 {
        return Err(error("Invalid Stellar StrKey length"));
    }

    let payload = &decoded[..33];
    let checksum = (decoded[33] as u16) | ((decoded[34] as u16) << 8);
    if crc16_xmodem(payload) != checksum {
        return Err(error("Invalid Stellar StrKey checksum"));
    }

    Ok((payload[0], payload[1..].to_vec()))
}

fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for byte in data {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../test-fixtures/ecies-v1-x25519.json");

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        recipient_key: String,
        plaintext: String,
        envelope: EciesEnvelope,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(FIXTURE).expect("fixture should parse")
    }

    fn envelope_json(fixture: &Fixture) -> String {
        serde_json::to_string(&fixture.envelope).expect("envelope should serialize")
    }

    #[test]
    fn decrypts_the_shared_conformance_fixture() {
        let fixture = fixture();
        let decryptor = EciesDecryptor::new(&fixture.recipient_key).unwrap();

        let plaintext = decryptor.decrypt(&envelope_json(&fixture)).unwrap();
        assert_eq!(plaintext, fixture.plaintext);
    }

    #[test]
    fn decrypts_webhook_body_and_checks_ephemeral_header() {
        let fixture = fixture();
        let decryptor = EciesDecryptor::new(&fixture.recipient_key).unwrap();
        let body = envelope_json(&fixture);

        assert!(decryptor
            .decrypt_webhook(&body, Some(&fixture.envelope.epk))
            .is_ok());
        assert!(decryptor
            .decrypt_webhook(&body, Some(&BASE64.encode([0u8; 32])))
            .is_err());
    }

    #[test]
    fn rejects_the_wrong_private_key() {
        let fixture = fixture();
        let decryptor = EciesDecryptor::new(&BASE64.encode([7u8; 32])).unwrap();

        assert!(decryptor.decrypt(&envelope_json(&fixture)).is_err());
    }

    #[test]
    fn rejects_a_tampered_ciphertext() {
        let fixture = fixture();
        let mut envelope = fixture.envelope.clone();
        let mut ciphertext = BASE64.decode(&envelope.ct).unwrap();
        ciphertext[0] ^= 0xFF;
        envelope.ct = BASE64.encode(ciphertext);

        let decryptor = EciesDecryptor::new(&fixture.recipient_key).unwrap();
        let result = decryptor.decrypt(&serde_json::to_string(&envelope).unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn rejects_an_unsupported_curve() {
        let fixture = fixture();
        let mut envelope = fixture.envelope.clone();
        envelope.curve = "secp256k1".to_string();

        let result = parse_envelope(&serde_json::to_string(&envelope).unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn decodes_a_stellar_public_strkey() {
        // Public value only; validates base32 + CRC16 without a secret literal.
        let (version, payload) =
            decode_strkey("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF").unwrap();
        assert_eq!(version, ED25519_PUBLIC_KEY_VERSION);
        assert_eq!(payload.len(), 32);
    }
}
