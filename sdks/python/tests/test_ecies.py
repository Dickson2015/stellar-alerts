import base64
import copy
import json
import unittest
from pathlib import Path

from stellar_alerts_webhook.decryptor import (
    EciesDecryptionError,
    EciesDecryptor,
    EPHEMERAL_KEY_HEADER,
    parse_envelope,
    resolve_recipient_public_key_for_test,
    resolve_x25519_private_key,
)

FIXTURE = json.loads(
    (Path(__file__).resolve().parents[2] / "test-fixtures" / "ecies-v1-x25519.json").read_text()
)


class EciesFixtureTests(unittest.TestCase):
    def test_decrypts_the_shared_conformance_fixture(self):
        decryptor = EciesDecryptor(FIXTURE["recipientKey"])
        self.assertEqual(decryptor.decrypt(FIXTURE["envelope"]), FIXTURE["plaintext"])
        self.assertEqual(
            json.loads(decryptor.decrypt(json.dumps(FIXTURE["envelope"]))),
            json.loads(FIXTURE["plaintext"]),
        )

    def test_decrypts_webhook_body_and_checks_ephemeral_header(self):
        decryptor = EciesDecryptor(FIXTURE["recipientKey"])
        body = json.dumps(FIXTURE["envelope"])

        self.assertEqual(
            decryptor.decrypt_webhook(body, FIXTURE["envelope"]["epk"]),
            FIXTURE["plaintext"],
        )

        other_header = base64.b64encode(b"x" * 32).decode("ascii")
        with self.assertRaises(EciesDecryptionError):
            decryptor.decrypt_webhook(body, other_header)

    def test_rejects_the_wrong_private_key(self):
        wrong = EciesDecryptor(base64.b64encode(b"w" * 32).decode("ascii"))
        with self.assertRaisesRegex(EciesDecryptionError, "failed authentication"):
            wrong.decrypt(FIXTURE["envelope"])

    def test_rejects_tampered_ciphertext_and_tag(self):
        decryptor = EciesDecryptor(FIXTURE["recipientKey"])

        tampered_ct = copy.deepcopy(FIXTURE["envelope"])
        raw = bytearray(base64.b64decode(tampered_ct["ct"]))
        raw[0] ^= 0xFF
        tampered_ct["ct"] = base64.b64encode(bytes(raw)).decode("ascii")
        with self.assertRaisesRegex(EciesDecryptionError, "failed authentication"):
            decryptor.decrypt(tampered_ct)

        tampered_tag = copy.deepcopy(FIXTURE["envelope"])
        tampered_tag["tag"] = base64.b64encode(b"\x00" * 16).decode("ascii")
        with self.assertRaisesRegex(EciesDecryptionError, "failed authentication"):
            decryptor.decrypt(tampered_tag)

    def test_rejects_malformed_envelopes(self):
        decryptor = EciesDecryptor(FIXTURE["recipientKey"])

        with self.assertRaises(EciesDecryptionError):
            decryptor.decrypt("not-json")

        unsupported = copy.deepcopy(FIXTURE["envelope"])
        unsupported["curve"] = "secp256k1"
        with self.assertRaisesRegex(EciesDecryptionError, "Unsupported"):
            parse_envelope(unsupported)

        short_iv = copy.deepcopy(FIXTURE["envelope"])
        short_iv["iv"] = base64.b64encode(b"short").decode("ascii")
        with self.assertRaisesRegex(EciesDecryptionError, "nonce"):
            decryptor.decrypt(short_iv)


class KeyNormalizationTests(unittest.TestCase):
    def test_accepts_prefixed_hex_and_raw_keys(self):
        raw = b"k" * 32
        expected = resolve_x25519_private_key(raw)

        self.assertEqual(
            resolve_x25519_private_key("x25519:" + raw.hex()),
            expected,
        )
        self.assertEqual(
            resolve_x25519_private_key("x25519:" + base64.b64encode(raw).decode("ascii")),
            expected,
        )
        self.assertEqual(
            resolve_x25519_private_key(base64.b64encode(raw).decode("ascii")),
            expected,
        )

    def test_converts_a_stellar_public_key_to_x25519(self):
        # Public value only — no secret is committed for this conformance check.
        stellar_address = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
        converted = resolve_recipient_public_key_for_test(stellar_address)
        self.assertEqual(len(converted), 32)

    def test_rejects_secp256k1_private_keys(self):
        with self.assertRaisesRegex(EciesDecryptionError, "secp256k1"):
            resolve_x25519_private_key("secp256k1:" + "11" * 32)


if __name__ == "__main__":
    unittest.main()
