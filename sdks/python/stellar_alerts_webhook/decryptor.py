"""End-to-end decryption for Stellar Alerts encrypted webhook deliveries.

The API can seal a webhook body with ECIES (``stellar-alerts-ecies-v1``):

* a fresh ephemeral X25519 key pair is generated per delivery,
* the AES-256-GCM key is derived with HKDF-SHA256 from the ECDH shared secret,
* the ephemeral public key is sent in ``Stellar-Alerts-Ephemeral-Key``,
* the request body is a JSON envelope with the nonce, tag and ciphertext.

This module decrypts that envelope with the subscriber's private key. The
same private key may be supplied as:

* a Stellar ``S...`` secret seed (converted to X25519 exactly like the API),
* ``x25519:<base64|hex>`` or ``ed25519:<base64|hex>``,
* a raw 32-byte key as base64 or hex.

See ``sdks/test-fixtures/ecies-v1-x25519.json`` for a conformance vector.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, Mapping, Optional, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ECIES_VERSION = 1
ECIES_ALGORITHM = "AES-256-GCM"
ECIES_INFO_PREFIX = "stellar-alerts-ecies-v1"
ECIES_KEY_BYTES = 32
ECIES_IV_BYTES = 12
ECIES_TAG_BYTES = 16
EPHEMERAL_KEY_HEADER = "Stellar-Alerts-Ephemeral-Key"
ENCRYPTION_HEADER = "Stellar-Alerts-Encryption"

_ED25519_PUBLIC_KEY_VERSION = 6 << 3  # 'G'
_ED25519_SECRET_KEY_VERSION = 18 << 3  # 'S'
_FIELD_PRIME = 2**255 - 19


class EciesDecryptionError(ValueError):
    """Raised when an envelope cannot be authenticated or parsed."""


def _crc16_xmodem(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _decode_strkey(value: str) -> tuple[int, bytes]:
    """Decodes a Stellar G.../S... StrKey into (version byte, 32-byte payload)."""
    try:
        padded = value + "=" * ((8 - len(value) % 8) % 8)
        decoded = base64.b32decode(padded, casefold=False)
    except Exception as exc:  # noqa: BLE001 - surface a single typed error
        raise EciesDecryptionError("Invalid Stellar StrKey encoding") from exc

    if len(decoded) != 35:
        raise EciesDecryptionError("Invalid Stellar StrKey length")

    payload, checksum_bytes = decoded[:-2], decoded[-2:]
    checksum = int.from_bytes(checksum_bytes, "little")
    if _crc16_xmodem(payload) != checksum:
        raise EciesDecryptionError("Invalid Stellar StrKey checksum")

    return payload[0], payload[1:]


def _ed25519_public_to_x25519(public_key: bytes) -> bytes:
    if len(public_key) != 32:
        raise EciesDecryptionError("Ed25519 public key must be 32 bytes")

    y = int.from_bytes(public_key, "little") & ((1 << 255) - 1)
    if y >= _FIELD_PRIME:
        raise EciesDecryptionError("Invalid Ed25519 public key")

    # Montgomery u = (1 + y) / (1 - y) mod p. y == 1 has no valid mapping.
    denominator = (1 - y) % _FIELD_PRIME
    if denominator == 0:
        raise EciesDecryptionError("Ed25519 public key cannot be converted to X25519")
    u = (1 + y) * pow(denominator, _FIELD_PRIME - 2, _FIELD_PRIME) % _FIELD_PRIME
    return u.to_bytes(32, "little")


def _ed25519_seed_to_x25519(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise EciesDecryptionError("Ed25519 secret seed must be 32 bytes")
    digest = bytearray(hashlib.sha512(seed).digest()[:32])
    digest[0] &= 248
    digest[31] &= 127
    digest[31] |= 64
    return bytes(digest)


def _decode_raw_key(value: str) -> bytes:
    try:
        if len(value) == 64 and all(char in "0123456789abcdefABCDEF" for char in value):
            return bytes.fromhex(value)
        return base64.b64decode(value, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise EciesDecryptionError("Invalid base64/hex key") from exc


def resolve_x25519_private_key(private_key: Union[str, bytes]) -> bytes:
    """Normalizes any supported private key form into a 32-byte X25519 key."""
    if isinstance(private_key, bytes):
        if len(private_key) == ECIES_KEY_BYTES:
            return private_key
        raise EciesDecryptionError("Raw private key must be 32 bytes")

    if not isinstance(private_key, str) or not private_key.strip():
        raise EciesDecryptionError("Recipient private key is required")

    value = private_key.strip()

    if value.startswith("x25519:"):
        resolved = _decode_raw_key(value[len("x25519:") :])
        if len(resolved) != ECIES_KEY_BYTES:
            raise EciesDecryptionError("X25519 private key must be 32 bytes")
        return resolved

    if value.startswith("ed25519:"):
        seed = _decode_raw_key(value[len("ed25519:") :])
        return _ed25519_seed_to_x25519(seed)

    if value.startswith("secp256k1:"):
        raise EciesDecryptionError(
            "This SDK decrypts X25519 envelopes; secp256k1 recipients must use a secp256k1 SDK"
        )

    if len(value) == 56 and value[0] in ("S", "G"):
        version, payload = _decode_strkey(value)
        if version == _ED25519_SECRET_KEY_VERSION:
            return _ed25519_seed_to_x25519(payload)
        if version == _ED25519_PUBLIC_KEY_VERSION:
            raise EciesDecryptionError("Expected a Stellar secret seed (S...), got a public key")
        raise EciesDecryptionError("Unsupported Stellar StrKey version")

    resolved = _decode_raw_key(value)
    if len(resolved) != ECIES_KEY_BYTES:
        raise EciesDecryptionError("Private key must be 32 bytes")
    return resolved


def resolve_recipient_public_key_for_test(public_key: str) -> bytes:
    """Converts a Stellar G.../x25519 key to its raw X25519 form.

    Exposed for tests and for applications that need to publish their
    encryption key; the API performs the same conversion when encrypting.
    """
    value = public_key.strip()
    if len(value) == 56 and value[0] == "G":
        version, payload = _decode_strkey(value)
        if version != _ED25519_PUBLIC_KEY_VERSION:
            raise EciesDecryptionError("Expected a Stellar public key (G...)")
        return _ed25519_public_to_x25519(payload)

    if value.startswith("x25519:"):
        raw = _decode_raw_key(value[len("x25519:") :])
    elif value.startswith("ed25519:"):
        return _ed25519_public_to_x25519(_decode_raw_key(value[len("ed25519:") :]))
    else:
        raw = _decode_raw_key(value)

    if len(raw) != ECIES_KEY_BYTES:
        raise EciesDecryptionError("Public key must be 32 bytes")
    return raw


def _decode_b64(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise EciesDecryptionError(f"Envelope field '{field}' must be a string")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise EciesDecryptionError(f"Envelope field '{field}' is not valid base64") from exc


def parse_envelope(envelope: Union[str, bytes, Mapping[str, Any]]) -> Dict[str, Any]:
    """Parses and structurally validates an ECIES envelope."""
    if isinstance(envelope, (str, bytes)):
        try:
            parsed = json.loads(envelope)
        except (TypeError, ValueError) as exc:
            raise EciesDecryptionError("Invalid ECIES envelope JSON") from exc
    elif isinstance(envelope, Mapping):
        parsed = dict(envelope)
    else:
        raise EciesDecryptionError("Invalid ECIES envelope")

    if (
        parsed.get("v") != ECIES_VERSION
        or parsed.get("alg") != ECIES_ALGORITHM
        or parsed.get("curve") != "x25519"
    ):
        raise EciesDecryptionError("Unsupported ECIES envelope version, algorithm or curve")

    ephemeral = _decode_b64(parsed.get("epk"), "epk")
    iv = _decode_b64(parsed.get("iv"), "iv")
    tag = _decode_b64(parsed.get("tag"), "tag")
    ciphertext = _decode_b64(parsed.get("ct"), "ct")

    if len(ephemeral) != ECIES_KEY_BYTES:
        raise EciesDecryptionError("Invalid ephemeral public key length")
    if len(iv) != ECIES_IV_BYTES:
        raise EciesDecryptionError("Invalid AES-GCM nonce length")
    if len(tag) != ECIES_TAG_BYTES:
        raise EciesDecryptionError("Invalid AES-GCM tag length")

    return {
        "curve": "x25519",
        "epk": ephemeral,
        "iv": iv,
        "tag": tag,
        "ct": ciphertext,
    }


class EciesDecryptor:
    """Decrypts ``stellar-alerts-ecies-v1`` webhook envelopes."""

    def __init__(self, private_key: Union[str, bytes]):
        self._private_key = resolve_x25519_private_key(private_key)

    def decrypt(self, envelope: Union[str, bytes, Mapping[str, Any]]) -> str:
        parsed = parse_envelope(envelope)
        info = f"{ECIES_INFO_PREFIX}:x25519".encode("utf-8")

        try:
            shared_secret = X25519PrivateKey.from_private_bytes(
                self._private_key
            ).exchange(X25519PublicKey.from_public_bytes(parsed["epk"]))
        except Exception as exc:  # noqa: BLE001
            raise EciesDecryptionError("ECDH key agreement failed") from exc

        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=ECIES_KEY_BYTES,
            salt=parsed["epk"],
            info=info,
        ).derive(shared_secret)

        try:
            plaintext = AESGCM(aes_key).decrypt(
                parsed["iv"], parsed["ct"] + parsed["tag"], info
            )
        except Exception as exc:  # noqa: BLE001 - InvalidTag is intentionally opaque
            raise EciesDecryptionError(
                "Encrypted webhook payload failed authentication"
            ) from exc

        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EciesDecryptionError("Decrypted payload is not valid UTF-8") from exc

    def decrypt_webhook(
        self,
        body: Union[str, bytes],
        ephemeral_key_header: Optional[str] = None,
    ) -> str:
        """Decrypts a raw request body and, when supplied, checks the header.

        The header value must match the envelope's ephemeral key; a mismatch
        means a proxy substituted one of the two and the delivery must be
        rejected.
        """
        parsed = parse_envelope(body)
        if ephemeral_key_header is not None:
            header_bytes = _decode_b64(ephemeral_key_header, "ephemeral key header")
            if header_bytes != parsed["epk"]:
                raise EciesDecryptionError(
                    "Stellar-Alerts-Ephemeral-Key does not match the envelope"
                )
        return self.decrypt(body)
