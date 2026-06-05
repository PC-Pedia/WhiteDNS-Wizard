package xui

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoteUploadCommandUsesPOSIXParentAndClearErrors(t *testing.T) {
	script := remoteUploadScript("/opt/wdns-wizard/3x-ui/docker-compose.yml", "/opt/wdns-wizard/3x-ui/docker-compose.yml.tmp", 0o644)

	for _, want := range []string{
		"parent='/opt/wdns-wizard/3x-ui'",
		"tmp='/opt/wdns-wizard/3x-ui/docker-compose.yml.tmp'",
		"target='/opt/wdns-wizard/3x-ui/docker-compose.yml'",
		"mkdir -p \"$parent\"",
		"remote upload parent is not writable: $parent",
		"remote upload parent does not exist: $parent",
		"remote upload temp write failed: $tmp",
		"chmod 0644 \"$tmp\"",
		"mv -f \"$tmp\" \"$target\"",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("upload script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, `\opt\wdns-wizard`) {
		t.Fatalf("upload script should use POSIX remote paths:\n%s", script)
	}

	cmd := remoteUploadCommand("/opt/wdns-wizard/3x-ui/docker-compose.yml", "/opt/wdns-wizard/3x-ui/docker-compose.yml.tmp", 0o644)
	if !strings.HasPrefix(cmd, "sh -lc ") {
		t.Fatalf("upload command should run through sh -lc:\n%s", cmd)
	}
}

func TestSignerFromFileWithEncryptedKeyPassphrase(t *testing.T) {
	keyPath := writeTestPrivateKey(t, true, "secret-passphrase")

	signer, err := signerFromFile(keyPath, "secret-passphrase")
	if err != nil {
		t.Fatalf("signerFromFile returned error: %v", err)
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}
}

func TestSignerFromFileWithEncryptedKeyWrongPassphrase(t *testing.T) {
	keyPath := writeTestPrivateKey(t, true, "secret-passphrase")

	_, err := signerFromFile(keyPath, "wrong-passphrase")
	if err == nil {
		t.Fatal("expected passphrase error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "decrypt ssh key") {
		t.Fatalf("error = %v", err)
	}
}

func TestSignerFromFileWithEncryptedKeyMissingPassphrase(t *testing.T) {
	keyPath := writeTestPrivateKey(t, true, "secret-passphrase")

	_, err := signerFromFile(keyPath, "")
	if err == nil {
		t.Fatal("expected missing passphrase error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "requires a passphrase") {
		t.Fatalf("error = %v", err)
	}
}

func TestSignerFromFileWithUnencryptedKeyAndBlankPassphrase(t *testing.T) {
	keyPath := writeTestPrivateKey(t, false, "")

	signer, err := signerFromFile(keyPath, "")
	if err != nil {
		t.Fatalf("signerFromFile returned error: %v", err)
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}
}

func writeTestPrivateKey(t *testing.T, encrypted bool, passphrase string) string {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if encrypted {
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(passphrase), x509.PEMCipherAES256)
		if err != nil {
			t.Fatalf("encrypt key: %v", err)
		}
	}
	keyPath := filepath.Join(t.TempDir(), "id_rsa")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return keyPath
}
