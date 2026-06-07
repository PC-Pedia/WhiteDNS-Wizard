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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/whitedns/wdns-wizard/internal/acme"
	"github.com/whitedns/wdns-wizard/internal/credentials"
	"github.com/whitedns/wdns-wizard/internal/output"
)

func TestPublicACMEUsesWildcardRequestAndCoversManagedTLSHosts(t *testing.T) {
	requestDomains := publicACMERequestDomains("example.com")
	if len(requestDomains) != 1 || requestDomains[0] != "*.example.com" {
		t.Fatalf("request domains = %+v, want wildcard only", requestDomains)
	}

	covered := publicACMECoveredHostnames("example.com")
	for _, want := range []string{
		"direct.example.com",
		"hy2.example.com",
		"tor-vless-ws.example.com",
		"tor-vless-ws-8443.example.com",
		"tor-hy2.example.com",
		"tor-direct.example.com",
	} {
		if !containsString(covered, want) {
			t.Fatalf("covered hostnames = %+v, missing %s", covered, want)
		}
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "public.pem")
	keyPath := filepath.Join(dir, "public.key")
	writeSelfSignedWildcardCert(t, certPath, keyPath, "*.example.com")
	project := projectData{Paths: output.ProjectPaths{PublicCert: certPath, PublicKey: keyPath}}
	if !project.publicCertFresh(covered) {
		t.Fatal("wildcard certificate should be fresh for managed public TLS hostnames")
	}
}

func TestEnsureCertificatesSkipsPreflightAndIssuerForFreshPublicCert(t *testing.T) {
	root := t.TempDir()
	paths := output.Paths(root, "example.com")
	writeRequiredOriginFiles(t, paths)
	writeSelfSignedWildcardCert(t, paths.PublicCert, paths.PublicKey, "*.example.com")
	project := projectData{Root: root, Domain: "example.com", Paths: paths}
	preflight := &recordingACMEPreflight{}
	issuer := &recordingIssuer{}

	err := (Provisioner{ACMEPreflight: preflight, Issuer: issuer}).ensureCertificates(context.Background(), project, Input{}, newProgressRecorder(nil))
	if err != nil {
		t.Fatalf("ensureCertificates returned error: %v", err)
	}
	if preflight.called {
		t.Fatal("preflight should not run for a fresh public certificate")
	}
	if issuer.called {
		t.Fatal("issuer should not run for a fresh public certificate")
	}
}

func TestEnsureCertificatesRunsPreflightBeforeIssuer(t *testing.T) {
	root := t.TempDir()
	paths := output.Paths(root, "example.com")
	writeRequiredOriginFiles(t, paths)
	saveTestCredentials(t, root)
	project := projectData{Root: root, Domain: "example.com", Paths: paths}
	preflight := &recordingACMEPreflight{}
	issuer := &recordingIssuer{}

	err := (Provisioner{ACMEPreflight: preflight, Issuer: issuer}).ensureCertificates(context.Background(), project, Input{}, newProgressRecorder(nil))
	if err != nil {
		t.Fatalf("ensureCertificates returned error: %v", err)
	}
	if !preflight.called || preflight.domain != "example.com" {
		t.Fatalf("preflight called/domain = %t/%q, want true/example.com", preflight.called, preflight.domain)
	}
	if !issuer.called {
		t.Fatal("issuer should run after successful preflight")
	}
}

func TestEnsureCertificatesStopsWhenPreflightFails(t *testing.T) {
	root := t.TempDir()
	paths := output.Paths(root, "example.com")
	writeRequiredOriginFiles(t, paths)
	saveTestCredentials(t, root)
	project := projectData{Root: root, Domain: "example.com", Paths: paths}
	preflight := &recordingACMEPreflight{err: acme.PreflightError{
		Kind:   acme.PreflightKindDNS,
		Domain: "example.com",
		Detail: "SOA _acme-challenge.example.com. @1.1.1.1:53 returned REFUSED",
	}}
	issuer := &recordingIssuer{}

	err := (Provisioner{ACMEPreflight: preflight, Issuer: issuer}).ensureCertificates(context.Background(), project, Input{}, newProgressRecorder(nil))
	if !acme.IsZoneOrDNSPreflightError(err) {
		t.Fatalf("error = %T %[1]v, want ACME DNS preflight error", err)
	}
	if issuer.called {
		t.Fatal("issuer should not run when preflight fails")
	}
}

type recordingACMEPreflight struct {
	called bool
	domain string
	err    error
}

func (r *recordingACMEPreflight) Check(ctx context.Context, input acme.PreflightInput) error {
	r.called = true
	r.domain = input.Domain
	return r.err
}

type recordingIssuer struct {
	called bool
}

func (r *recordingIssuer) Obtain(ctx context.Context, input acme.Input) (acme.Certificate, error) {
	r.called = true
	if len(input.Domains) == 0 {
		return acme.Certificate{}, errors.New("domains missing")
	}
	return acme.Certificate{CertPEM: "public-cert", KeyPEM: "public-key"}, nil
}

func writeSelfSignedWildcardCert(t *testing.T, certPath, keyPath, hostname string) {
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
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func writeRequiredOriginFiles(t *testing.T, paths output.ProjectPaths) {
	t.Helper()
	for _, dir := range []string{filepath.Dir(paths.OriginCert), filepath.Dir(paths.PublicCert)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(paths.OriginCert, []byte("origin-cert"), 0o644); err != nil {
		t.Fatalf("write origin cert: %v", err)
	}
	if err := os.WriteFile(paths.OriginKey, []byte("origin-key"), 0o600); err != nil {
		t.Fatalf("write origin key: %v", err)
	}
}

func saveTestCredentials(t *testing.T, root string) {
	t.Helper()
	if err := credentials.Save(root, credentials.CloudflareCredentials{AccountID: "account-id", APIToken: "token"}); err != nil {
		t.Fatalf("save credentials: %v", err)
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
