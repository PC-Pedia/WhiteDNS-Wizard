package xui

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/whitedns/wdns-wizard/internal/acme"
)

func TestRemoteLegoIssuerObtainsWithDockerFallbackCommand(t *testing.T) {
	certPEM, keyPEM := testCertificatePair(t, "*.example.com")
	remote := &fakeRemote{outputs: map[string]string{
		"certificates/_.example.com.crt": certPEM,
		"certificates/_.example.com.key": keyPEM,
	}}
	token := "secret-cloudflare-token"

	cert, err := (RemoteLegoIssuer{
		Now: func() time.Time { return time.Unix(0, 1234) },
	}).Obtain(context.Background(), remote, acme.Input{
		Email:           "admin@example.com",
		CloudflareToken: token,
		Domains:         []string{"*.example.com"},
	})
	if err != nil {
		t.Fatalf("Obtain returned error: %v", err)
	}
	if cert.CertPEM != certPEM || cert.KeyPEM != keyPEM {
		t.Fatalf("cert = %#v, want remote PEM pair", cert)
	}

	envPath := "/tmp/wdns-acme-_.example.com-1234.env"
	envFile := string(remote.uploads[envPath])
	if remote.uploadPerms[envPath] != 0o600 {
		t.Fatalf("env upload perm = %o, want 0600", remote.uploadPerms[envPath])
	}
	for _, want := range []string{
		"CLOUDFLARE_DNS_API_TOKEN=" + token,
		"CLOUDFLARE_ZONE_API_TOKEN=" + token,
		"CLOUDFLARE_PROPAGATION_TIMEOUT=180",
		"CLOUDFLARE_POLLING_INTERVAL=5",
	} {
		if !strings.Contains(envFile, want) {
			t.Fatalf("env file missing %q:\n%s", want, envFile)
		}
	}

	for _, command := range remote.commands {
		if strings.Contains(command, token) {
			t.Fatalf("remote command exposed token:\n%s", command)
		}
	}
	issueCommand := findCommand(remote.commands, "docker run --rm")
	if issueCommand == "" {
		t.Fatalf("remote commands missing docker fallback:\n%v", remote.commands)
	}
	for _, want := range []string{
		"goacme/lego:v4.24.0",
		"--dns cloudflare",
		"--key-type ec256",
		"--dns-timeout 5",
		"--dns.resolvers",
		"1.1.1.1:53",
		"8.8.8.8:53",
		"--dns.propagation-wait",
		"45s",
		":/data",
		"--path /data",
		"certificates/$cert_base.crt",
		"certificates/$cert_base.key",
	} {
		if !strings.Contains(issueCommand, want) {
			t.Fatalf("issue command missing %q:\n%s", want, issueCommand)
		}
	}
	if !containsCommand(remote.commands, "rm -rf '/tmp/wdns-acme-_.example.com-1234' '/tmp/wdns-acme-_.example.com-1234.env'") {
		t.Fatalf("remote commands missing cleanup:\n%v", remote.commands)
	}
}

func TestRemoteLegoIssuerSanitizesWildcardFilename(t *testing.T) {
	if got := remoteLegoCertBaseName("*.example.com"); got != "_.example.com" {
		t.Fatalf("cert base = %q, want _.example.com", got)
	}
}

func TestRemoteLegoIssuerRejectsInvalidPEMPair(t *testing.T) {
	remote := &fakeRemote{outputs: map[string]string{
		"certificates/_.example.com.crt": "not a cert",
		"certificates/_.example.com.key": "not a key",
	}}

	_, err := (RemoteLegoIssuer{
		Now: func() time.Time { return time.Unix(0, 55) },
	}).Obtain(context.Background(), remote, acme.Input{
		Email:           "admin@example.com",
		CloudflareToken: "secret",
		Domains:         []string{"*.example.com"},
	})
	if err == nil || !strings.Contains(err.Error(), "validate remote ACME certificate") {
		t.Fatalf("error = %v, want PEM validation error", err)
	}
	if !containsCommand(remote.commands, "rm -rf '/tmp/wdns-acme-_.example.com-55' '/tmp/wdns-acme-_.example.com-55.env'") {
		t.Fatalf("remote commands missing cleanup after validation failure:\n%v", remote.commands)
	}
}

func TestRemoteLegoIssuerCleansUpAfterIssuanceError(t *testing.T) {
	remote := &fakeRemote{failOnce: map[string]error{
		"docker run --rm": errors.New("remote command failed: timeout"),
	}}

	_, err := (RemoteLegoIssuer{
		Now: func() time.Time { return time.Unix(0, 77) },
	}).Obtain(context.Background(), remote, acme.Input{
		Email:           "admin@example.com",
		CloudflareToken: "secret",
		Domains:         []string{"*.example.com"},
	})
	if err == nil || !strings.Contains(err.Error(), "run remote ACME issuance") {
		t.Fatalf("error = %v, want remote issuance error", err)
	}
	if containsCommand(remote.commands, "cat '/tmp/wdns-acme-_.example.com-77/certificates/_.example.com.crt'") {
		t.Fatalf("issuer should not read cert after issuance failure:\n%v", remote.commands)
	}
	if !containsCommand(remote.commands, "rm -rf '/tmp/wdns-acme-_.example.com-77' '/tmp/wdns-acme-_.example.com-77.env'") {
		t.Fatalf("remote commands missing cleanup after issuance failure:\n%v", remote.commands)
	}
}

func testCertificatePair(t *testing.T, hostname string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{hostname},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func findCommand(commands []string, pattern string) string {
	for _, command := range commands {
		if strings.Contains(command, pattern) {
			return command
		}
	}
	return ""
}

func containsCommand(commands []string, pattern string) bool {
	return findCommand(commands, pattern) != ""
}
