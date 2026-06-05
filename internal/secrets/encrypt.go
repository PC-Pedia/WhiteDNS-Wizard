package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"gopkg.in/yaml.v3"
)

const EnvKeyName = "WDNS_WIZARD_SECRETS_KEY"

type Envelope struct {
	Version    int    `yaml:"version" json:"version"`
	Algorithm  string `yaml:"algorithm" json:"algorithm"`
	Nonce      string `yaml:"nonce" json:"nonce"`
	Ciphertext string `yaml:"ciphertext" json:"ciphertext"`
	CreatedAt  string `yaml:"created_at" json:"created_at"`
}

func LoadKeyFromEnv() ([]byte, error) {
	raw := os.Getenv(EnvKeyName)
	if raw == "" {
		return nil, fmt.Errorf("%s must be set to a base64-encoded 32-byte key", EnvKeyName)
	}
	key, err := DecodeKey(raw)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func DecodeKey(raw string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%s must be base64: %w", EnvKeyName, err)
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("%s must decode to exactly 32 bytes", EnvKeyName)
	}
	return key, nil
}

func LoadOrCreateKey(keyPath string) ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv(EnvKeyName))
	if raw != "" {
		return DecodeKey(raw)
	}

	if keyPath != "" {
		if data, err := os.ReadFile(keyPath); err == nil {
			key, err := DecodeKey(string(data))
			if err != nil {
				return nil, fmt.Errorf("read secrets key file %s: %w", keyPath, err)
			}
			_ = os.Setenv(EnvKeyName, strings.TrimSpace(string(data)))
			return key, nil
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read secrets key file %s: %w", keyPath, err)
		}
	}

	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate secrets key: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	if keyPath != "" {
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
			return nil, fmt.Errorf("create secrets key directory: %w", err)
		}
		if err := os.WriteFile(keyPath, []byte(encoded+"\n"), 0o600); err != nil {
			return nil, fmt.Errorf("write secrets key file %s: %w", keyPath, err)
		}
	}
	_ = os.Setenv(EnvKeyName, encoded)
	return key, nil
}

func EncryptMap(values map[string]string, key []byte) (Envelope, error) {
	plaintext, err := yaml.Marshal(values)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal secrets: %w", err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return Envelope{}, fmt.Errorf("create cipher: %w", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return Envelope{
		Version:    1,
		Algorithm:  "XCHACHA20-POLY1305",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func DecryptMap(envelope Envelope, key []byte) (map[string]string, error) {
	if envelope.Algorithm != "XCHACHA20-POLY1305" {
		return nil, fmt.Errorf("unsupported secrets algorithm %q", envelope.Algorithm)
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt secrets: %w", err)
	}
	var values map[string]string
	if err := yaml.Unmarshal(plaintext, &values); err != nil {
		return nil, fmt.Errorf("unmarshal secrets: %w", err)
	}
	return values, nil
}
