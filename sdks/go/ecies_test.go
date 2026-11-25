package webhook

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type eciesFixture struct {
	Curve               string        `json:"curve"`
	RecipientKey        string        `json:"recipientKey"`
	RecipientPublicKey  string        `json:"recipientPublicKey"`
	Plaintext           string        `json:"plaintext"`
	Envelope            EciesEnvelope `json:"envelope"`
}

func loadFixture(t *testing.T) eciesFixture {
	t.Helper()
	raw, err := os.ReadFile("../test-fixtures/ecies-v1-x25519.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture eciesFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return fixture
}

func TestDecryptsSharedConformanceFixture(t *testing.T) {
	fixture := loadFixture(t)
	decryptor, err := NewEciesDecryptor(fixture.RecipientKey)
	if err != nil {
		t.Fatalf("new decryptor: %v", err)
	}

	body, err := json.Marshal(fixture.Envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	plaintext, err := decryptor.Decrypt(body)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plaintext != fixture.Plaintext {
		t.Fatalf("plaintext mismatch\nwant: %s\ngot:  %s", fixture.Plaintext, plaintext)
	}
}

func TestDecryptWebhookChecksEphemeralHeader(t *testing.T) {
	fixture := loadFixture(t)
	decryptor, err := NewEciesDecryptor(fixture.RecipientKey)
	if err != nil {
		t.Fatalf("new decryptor: %v", err)
	}
	body, _ := json.Marshal(fixture.Envelope)

	if _, err := decryptor.DecryptWebhook(body, fixture.Envelope.Epk); err != nil {
		t.Fatalf("matching header rejected: %v", err)
	}

	other := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, err := decryptor.DecryptWebhook(body, other); err == nil {
		t.Fatal("expected mismatched ephemeral header to be rejected")
	}
}

func TestRejectsWrongPrivateKey(t *testing.T) {
	fixture := loadFixture(t)
	decryptor, err := NewEciesDecryptor(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("w", 32))))
	if err != nil {
		t.Fatalf("new decryptor: %v", err)
	}
	body, _ := json.Marshal(fixture.Envelope)

	if _, err := decryptor.Decrypt(body); err == nil {
		t.Fatal("expected decryption with the wrong key to fail")
	}
}

func TestRejectsTamperedEnvelope(t *testing.T) {
	fixture := loadFixture(t)
	decryptor, err := NewEciesDecryptor(fixture.RecipientKey)
	if err != nil {
		t.Fatalf("new decryptor: %v", err)
	}

	ciphertext, _ := base64.StdEncoding.DecodeString(fixture.Envelope.Ct)
	ciphertext[0] ^= 0xFF
	tampered := fixture.Envelope
	tampered.Ct = base64.StdEncoding.EncodeToString(ciphertext)
	body, _ := json.Marshal(tampered)

	if _, err := decryptor.Decrypt(body); err == nil {
		t.Fatal("expected tampered ciphertext to fail authentication")
	}
}

func TestRejectsUnsupportedCurve(t *testing.T) {
	fixture := loadFixture(t)
	envelope := fixture.Envelope
	envelope.Curve = "secp256k1"
	body, _ := json.Marshal(envelope)

	if _, err := ParseEciesEnvelope(body); err == nil {
		t.Fatal("expected unsupported curve to be rejected")
	}
}

func TestStrKeyDecoding(t *testing.T) {
	// Public value only; validates base32 + CRC16 without committing a secret.
	version, payload, err := decodeStrKey("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF")
	if err != nil {
		t.Fatalf("decode strkey: %v", err)
	}
	if version != ed25519PublicKeyVersion {
		t.Fatalf("unexpected version byte: %d", version)
	}
	if len(payload) != 32 {
		t.Fatalf("unexpected payload length: %d", len(payload))
	}
}
