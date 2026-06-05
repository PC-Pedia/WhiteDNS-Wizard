package secrets

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptDecryptMap(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	values := map[string]string{
		"cloudflare_token": "secret-token",
		"vless_uuid":       "uuid",
	}
	envelope, err := EncryptMap(values, key)
	if err != nil {
		t.Fatalf("EncryptMap returned error: %v", err)
	}
	if strings.Contains(envelope.Ciphertext, "secret-token") {
		t.Fatal("ciphertext leaked plaintext")
	}
	got, err := DecryptMap(envelope, key)
	if err != nil {
		t.Fatalf("DecryptMap returned error: %v", err)
	}
	if got["cloudflare_token"] != "secret-token" || got["vless_uuid"] != "uuid" {
		t.Fatalf("decrypted values = %+v", got)
	}
}

func TestLoadKeyFromEnv(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	t.Setenv(EnvKeyName, base64.StdEncoding.EncodeToString(key))
	got, err := LoadKeyFromEnv()
	if err != nil {
		t.Fatalf("LoadKeyFromEnv returned error: %v", err)
	}
	if string(got) != string(key) {
		t.Fatal("wrong key")
	}
}

func TestLoadKeyFromEnvRejectsWrongSize(t *testing.T) {
	t.Setenv(EnvKeyName, base64.StdEncoding.EncodeToString([]byte("short")))
	if _, err := LoadKeyFromEnv(); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadOrCreateKeyCreatesAndReusesFile(t *testing.T) {
	t.Setenv(EnvKeyName, "")
	keyPath := filepath.Join(t.TempDir(), ".secrets.key")
	first, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateKey create returned error: %v", err)
	}
	if len(first) != 32 {
		t.Fatalf("key length = %d", len(first))
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("key file perm = %o, want 600", got)
	}

	t.Setenv(EnvKeyName, "")
	second, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateKey reuse returned error: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("expected existing key to be reused")
	}
}

func TestGenerateIncludesRealitySecrets(t *testing.T) {
	generated, err := Generate()
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	for name, value := range map[string]string{
		"vless_8443_uuid":                 generated.VLESS8443UUID,
		"reality_vless_uuid":              generated.RealityVLESSUUID,
		"reality_private_key":             generated.RealityPrivateKey,
		"reality_public_key":              generated.RealityPublicKey,
		"reality_short_id":                generated.RealityShortID,
		"reality_mldsa65_seed":            generated.RealityMLDSA65Seed,
		"reality_mlkem_decryption":        generated.RealityMLKEMDecryption,
		"reality_mlkem_encryption":        generated.RealityMLKEMEncryption,
		"reality_sni":                     generated.RealitySNI,
		"hysteria2_obfs_password":         generated.Hysteria2ObfsPassword,
		"shadowsocks_server_password":     generated.ShadowsocksServerPass,
		"shadowsocks_client_password":     generated.ShadowsocksClientPass,
		"tor_vless_uuid":                  generated.TorVLESSUUID,
		"tor_vless_8443_uuid":             generated.TorVLESS8443UUID,
		"tor_direct_vless_uuid":           generated.TorDirectVLESSUUID,
		"tor_reality_vless_uuid":          generated.TorRealityVLESSUUID,
		"tor_reality_private_key":         generated.TorRealityPrivateKey,
		"tor_reality_public_key":          generated.TorRealityPublicKey,
		"tor_reality_short_id":            generated.TorRealityShortID,
		"tor_reality_mldsa65_seed":        generated.TorRealityMLDSA65Seed,
		"tor_reality_mlkem_decryption":    generated.TorRealityMLKEMDecrypt,
		"tor_reality_mlkem_encryption":    generated.TorRealityMLKEMEncrypt,
		"tor_reality_sni":                 generated.TorRealitySNI,
		"tor_hysteria2_password":          generated.TorHysteria2Password,
		"tor_hysteria2_obfs_password":     generated.TorHysteria2ObfsPass,
		"tor_shadowsocks_server_password": generated.TorShadowsocksServer,
		"tor_shadowsocks_client_password": generated.TorShadowsocksClient,
	} {
		if strings.TrimSpace(value) == "" {
			t.Fatalf("%s is empty", name)
		}
	}
	if !strings.HasPrefix(generated.RealityMLKEMDecryption, "mlkem768x25519plus.native.600s.") {
		t.Fatalf("unexpected reality decryption value: %s", generated.RealityMLKEMDecryption)
	}
	if !strings.HasPrefix(generated.RealityMLKEMEncryption, "mlkem768x25519plus.native.0rtt.") {
		t.Fatalf("unexpected reality encryption value: %s", generated.RealityMLKEMEncryption)
	}
	if !containsString(RealitySNICandidates(), generated.RealitySNI) {
		t.Fatalf("unexpected reality SNI: %s", generated.RealitySNI)
	}
	if !containsString(RealitySNICandidates(), generated.TorRealitySNI) {
		t.Fatalf("unexpected tor reality SNI: %s", generated.TorRealitySNI)
	}
	if !containsString([]string{"apple.com", "docker.com"}, generated.RealitySNI) ||
		!containsString([]string{"apple.com", "docker.com"}, generated.TorRealitySNI) {
		t.Fatalf("Reality SNI should be apple.com or docker.com, got reality=%s tor=%s", generated.RealitySNI, generated.TorRealitySNI)
	}
	values := PlaintextMap("token", generated, "origin-key")
	for _, key := range []string{
		"vless_8443_uuid",
		"reality_vless_uuid",
		"reality_private_key",
		"reality_public_key",
		"reality_short_id",
		"reality_mldsa65_seed",
		"reality_mlkem_decryption",
		"reality_mlkem_encryption",
		"reality_sni",
		"hysteria2_obfs_password",
		"shadowsocks_server_password",
		"shadowsocks_client_password",
		"tor_vless_uuid",
		"tor_vless_8443_uuid",
		"tor_direct_vless_uuid",
		"tor_reality_vless_uuid",
		"tor_reality_private_key",
		"tor_reality_public_key",
		"tor_reality_short_id",
		"tor_reality_mldsa65_seed",
		"tor_reality_mlkem_decryption",
		"tor_reality_mlkem_encryption",
		"tor_reality_sni",
		"tor_hysteria2_password",
		"tor_hysteria2_obfs_password",
		"tor_shadowsocks_server_password",
		"tor_shadowsocks_client_password",
	} {
		if strings.TrimSpace(values[key]) == "" {
			t.Fatalf("PlaintextMap missing %s", key)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
