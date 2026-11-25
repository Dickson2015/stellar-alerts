package webhook

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// End-to-end decryption for Stellar Alerts encrypted webhook deliveries.
//
// The API seals payloads with ECIES (stellar-alerts-ecies-v1):
//
//   - ephemeral X25519 key pair per delivery,
//   - HKDF-SHA256 key derivation from the ECDH shared secret,
//   - AES-256-GCM encryption with the curve identifier as AAD,
//   - ephemeral public key in the Stellar-Alerts-Ephemeral-Key header and a
//     JSON envelope ({v,alg,curve,epk,iv,ct,tag}) as the request body.
//
// Private keys may be supplied as a Stellar S... secret seed, an
// x25519:/ed25519: prefixed base64/hex key, or an unprefixed 32-byte key.
// See sdks/test-fixtures/ecies-v1-x25519.json for a conformance vector.

const (
	EciesVersion          = 1
	EciesAlgorithm        = "AES-256-GCM"
	EciesCurve            = "x25519"
	EciesInfoPrefix       = "stellar-alerts-ecies-v1"
	EciesKeyBytes         = 32
	EciesIVBytes          = 12
	EciesTagBytes         = 16
	EphemeralKeyHeader    = "Stellar-Alerts-Ephemeral-Key"
	EciesEncryptionHeader = "Stellar-Alerts-Encryption"

	ed25519PublicKeyVersion = 6 << 3  // 'G'
	ed25519SecretKeyVersion = 18 << 3 // 'S'
)

// EciesEnvelope is the JSON request body of an encrypted delivery.
type EciesEnvelope struct {
	V     int    `json:"v"`
	Alg   string `json:"alg"`
	Curve string `json:"curve"`
	Epk   string `json:"epk"`
	Iv    string `json:"iv"`
	Ct    string `json:"ct"`
	Tag   string `json:"tag"`
}

// EciesDecryptionError is returned for any malformed or unauthentic envelope.
type EciesDecryptionError struct {
	Message string
}

func (e *EciesDecryptionError) Error() string {
	return e.Message
}

func eciesError(message string) error {
	return &EciesDecryptionError{Message: message}
}

// NewEciesDecryptor normalizes the subscriber's private key to X25519.
func NewEciesDecryptor(privateKey string) (*EciesDecryptor, error) {
	resolved, err := resolveX25519PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return &EciesDecryptor{privateKey: resolved}, nil
}

// EciesDecryptor decrypts stellar-alerts-ecies-v1 envelopes.
type EciesDecryptor struct {
	privateKey [EciesKeyBytes]byte
}

// Decrypt opens a JSON envelope (string or bytes) and returns the UTF-8 body.
func (d *EciesDecryptor) Decrypt(envelope []byte) (string, error) {
	parsed, err := parseEciesEnvelope(envelope)
	if err != nil {
		return "", err
	}

	sharedSecret, err := curve25519.X25519(d.privateKey[:], parsed.epk)
	if err != nil {
		return "", eciesError("ECDH key agreement failed")
	}

	info := []byte(EciesInfoPrefix + ":" + EciesCurve)
	reader := hkdf.New(sha256.New, sharedSecret, parsed.epk, info)
	aesKey := make([]byte, EciesKeyBytes)
	if _, err := io.ReadFull(reader, aesKey); err != nil {
		return "", eciesError("HKDF key derivation failed")
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", eciesError("AES-GCM initialization failed")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", eciesError("AES-GCM initialization failed")
	}

	sealed := append(append([]byte{}, parsed.ct...), parsed.tag...)
	plaintext, err := gcm.Open(nil, parsed.iv, sealed, info)
	if err != nil {
		return "", eciesError("Encrypted webhook payload failed authentication")
	}

	return string(plaintext), nil
}

// DecryptWebhook also verifies the Stellar-Alerts-Ephemeral-Key header against
// the envelope when the header is present.
func (d *EciesDecryptor) DecryptWebhook(body []byte, ephemeralKeyHeader string) (string, error) {
	parsed, err := parseEciesEnvelope(body)
	if err != nil {
		return "", err
	}

	if ephemeralKeyHeader != "" {
		header, err := decodeBase64(ephemeralKeyHeader)
		if err != nil {
			return "", eciesError("Stellar-Alerts-Ephemeral-Key is not valid base64")
		}
		if !equalBytes(header, parsed.epk) {
			return "", eciesError("Stellar-Alerts-Ephemeral-Key does not match the envelope")
		}
	}

	return d.Decrypt(body)
}

type parsedEciesEnvelope struct {
	epk []byte
	iv  []byte
	ct  []byte
	tag []byte
}

func parseEciesEnvelope(raw []byte) (*parsedEciesEnvelope, error) {
	var envelope EciesEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, eciesError("Invalid ECIES envelope JSON")
	}

	if envelope.V != EciesVersion ||
		envelope.Alg != EciesAlgorithm ||
		envelope.Curve != EciesCurve {
		return nil, eciesError("Unsupported ECIES envelope version, algorithm or curve")
	}

	epk, err := decodeBase64(envelope.Epk)
	if err != nil {
		return nil, eciesError("Envelope field 'epk' is not valid base64")
	}
	iv, err := decodeBase64(envelope.Iv)
	if err != nil {
		return nil, eciesError("Envelope field 'iv' is not valid base64")
	}
	ct, err := decodeBase64(envelope.Ct)
	if err != nil {
		return nil, eciesError("Envelope field 'ct' is not valid base64")
	}
	tag, err := decodeBase64(envelope.Tag)
	if err != nil {
		return nil, eciesError("Envelope field 'tag' is not valid base64")
	}

	if len(epk) != EciesKeyBytes {
		return nil, eciesError("Invalid ephemeral public key length")
	}
	if len(iv) != EciesIVBytes {
		return nil, eciesError("Invalid AES-GCM nonce length")
	}
	if len(tag) != EciesTagBytes {
		return nil, eciesError("Invalid AES-GCM tag length")
	}

	return &parsedEciesEnvelope{epk: epk, iv: iv, ct: ct, tag: tag}, nil
}

func resolveX25519PrivateKey(privateKey string) ([EciesKeyBytes]byte, error) {
	var zero [EciesKeyBytes]byte
	value := strings.TrimSpace(privateKey)
	if value == "" {
		return zero, eciesError("Recipient private key is required")
	}

	switch {
	case strings.HasPrefix(value, "x25519:"):
		raw, err := decodeRawKey(strings.TrimPrefix(value, "x25519:"))
		if err != nil || len(raw) != EciesKeyBytes {
			return zero, eciesError("X25519 private key must be 32 bytes")
		}
		var key [EciesKeyBytes]byte
		copy(key[:], raw)
		return key, nil

	case strings.HasPrefix(value, "ed25519:"):
		seed, err := decodeRawKey(strings.TrimPrefix(value, "ed25519:"))
		if err != nil || len(seed) != EciesKeyBytes {
			return zero, eciesError("Ed25519 secret key must be 32 bytes")
		}
		return ed25519SeedToX25519(seed), nil

	case strings.HasPrefix(value, "secp256k1:"):
		return zero, eciesError("This SDK decrypts X25519 envelopes; secp256k1 recipients must use a secp256k1 SDK")

	case len(value) == 56 && (value[0] == 'S' || value[0] == 'G'):
		version, payload, err := decodeStrKey(value)
		if err != nil {
			return zero, err
		}
		if version == ed25519SecretKeyVersion {
			return ed25519SeedToX25519(payload), nil
		}
		if version == ed25519PublicKeyVersion {
			return zero, eciesError("Expected a Stellar secret seed (S...), got a public key")
		}
		return zero, eciesError("Unsupported Stellar StrKey version")

	default:
		raw, err := decodeRawKey(value)
		if err != nil || len(raw) != EciesKeyBytes {
			return zero, eciesError("Private key must be 32 bytes (base64 or hex)")
		}
		var key [EciesKeyBytes]byte
		copy(key[:], raw)
		return key, nil
	}
}

func ed25519SeedToX25519(seed []byte) [EciesKeyBytes]byte {
	digest := sha512.Sum512(seed)
	var key [EciesKeyBytes]byte
	copy(key[:], digest[:EciesKeyBytes])
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return key
}

func decodeRawKey(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) == 64 {
		if decoded, err := hex.DecodeString(trimmed); err == nil {
			return decoded, nil
		}
	}
	return decodeBase64(trimmed)
}

func decodeBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
}

func decodeStrKey(value string) (byte, []byte, error) {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(value)
	if err != nil {
		return 0, nil, eciesError("Invalid Stellar StrKey encoding")
	}
	if len(decoded) != 35 {
		return 0, nil, eciesError("Invalid Stellar StrKey length")
	}

	payload := decoded[:33]
	checksum := int(decoded[33]) | int(decoded[34])<<8
	if crc16XModem(payload) != checksum {
		return 0, nil, eciesError("Invalid Stellar StrKey checksum")
	}
	return payload[0], payload[1:], nil
}

func crc16XModem(data []byte) int {
	crc := 0
	for _, b := range data {
		crc ^= int(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
			crc &= 0xFFFF
		}
	}
	return crc
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var diff byte
	for i := range left {
		diff |= left[i] ^ right[i]
	}
	return diff == 0
}

// ParseEciesEnvelope validates an envelope without decrypting it. Exported for
// applications that need to inspect the curve or ephemeral key first.
func ParseEciesEnvelope(raw []byte) (*EciesEnvelope, error) {
	var envelope EciesEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, eciesError("Invalid ECIES envelope JSON")
	}
	if _, err := parseEciesEnvelope(raw); err != nil {
		return nil, err
	}
	return &envelope, nil
}
