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
	"strings"
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

	err := (Provisioner{ACMEPreflight: preflight, Issuer: issuer}).ensureCertificates(context.Background(), nil, project, Input{}, newProgressRecorder(nil))
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

	err := (Provisioner{ACMEPreflight: preflight, Issuer: issuer}).ensureCertificates(context.Background(), nil, project, Input{}, newProgressRecorder(nil))
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

	err := (Provisioner{ACMEPreflight: preflight, Issuer: issuer}).ensureCertificates(context.Background(), nil, project, Input{}, newProgressRecorder(nil))
	if !acme.IsZoneOrDNSPreflightError(err) {
		t.Fatalf("error = %T %[1]v, want ACME DNS preflight error", err)
	}
	if issuer.called {
		t.Fatal("issuer should not run when preflight fails")
	}
}

func TestEnsureCertificatesFallsBackToRemoteIssuerForACMEConnectivity(t *testing.T) {
	root := t.TempDir()
	paths := output.Paths(root, "example.com")
	writeRequiredOriginFiles(t, paths)
	saveTestCredentials(t, root)
	project := projectData{Root: root, Domain: "example.com", Paths: paths}
	issuer := &recordingIssuer{err: acme.ConnectivityError{
		Operation: "creating the ACME client",
		Detail:    "net/http: TLS handshake timeout",
	}}
	remoteIssuer := &recordingRemoteIssuer{cert: acme.Certificate{CertPEM: "remote-cert", KeyPEM: "remote-key"}}

	err := (Provisioner{
		ACMEPreflight: &recordingACMEPreflight{},
		Issuer:        issuer,
		RemoteIssuer:  remoteIssuer,
	}).ensureCertificates(context.Background(), &fakeRemote{}, project, Input{}, newProgressRecorder(nil))
	if err != nil {
		t.Fatalf("ensureCertificates returned error: %v", err)
	}
	if !issuer.called {
		t.Fatal("local issuer should run first")
	}
	if !remoteIssuer.called {
		t.Fatal("remote issuer should run after local ACME connectivity failure")
	}
	if got := readFileString(t, paths.PublicCert); got != "remote-cert" {
		t.Fatalf("public cert = %q, want remote-cert", got)
	}
	if got := readFileString(t, paths.PublicKey); got != "remote-key" {
		t.Fatalf("public key = %q, want remote-key", got)
	}
}

func TestEnsureCertificatesDoesNotFallbackForGenericIssuerError(t *testing.T) {
	root := t.TempDir()
	paths := output.Paths(root, "example.com")
	writeRequiredOriginFiles(t, paths)
	saveTestCredentials(t, root)
	project := projectData{Root: root, Domain: "example.com", Paths: paths}
	issuer := &recordingIssuer{err: errors.New("register ACME account: unauthorized")}
	remoteIssuer := &recordingRemoteIssuer{cert: acme.Certificate{CertPEM: "remote-cert", KeyPEM: "remote-key"}}

	err := (Provisioner{
		ACMEPreflight: &recordingACMEPreflight{},
		Issuer:        issuer,
		RemoteIssuer:  remoteIssuer,
	}).ensureCertificates(context.Background(), &fakeRemote{}, project, Input{}, newProgressRecorder(nil))
	if err == nil {
		t.Fatal("expected generic issuer error")
	}
	if remoteIssuer.called {
		t.Fatal("remote issuer should not run for non-connectivity ACME errors")
	}
}

func TestEnsureCertificatesMapsACMENXDOMAINToDNSPreflightError(t *testing.T) {
	root := t.TempDir()
	paths := output.Paths(root, "example.com")
	writeRequiredOriginFiles(t, paths)
	saveTestCredentials(t, root)
	project := projectData{Root: root, Domain: "example.com", Paths: paths}
	issuer := &recordingIssuer{err: errors.New("obtain ACME certificate: urn:ietf:params:acme:error:dns :: DNS problem: NXDOMAIN looking up TXT for _acme-challenge.example.com")}
	remoteIssuer := &recordingRemoteIssuer{cert: acme.Certificate{CertPEM: "remote-cert", KeyPEM: "remote-key"}}

	err := (Provisioner{
		ACMEPreflight: &recordingACMEPreflight{},
		Issuer:        issuer,
		RemoteIssuer:  remoteIssuer,
	}).ensureCertificates(context.Background(), &fakeRemote{}, project, Input{}, newProgressRecorder(nil))
	if !acme.IsZoneOrDNSPreflightError(err) {
		t.Fatalf("error = %T %[1]v, want ACME DNS preflight error", err)
	}
	if !strings.Contains(err.Error(), "not a DNS record in the Cloudflare DNS records table") {
		t.Fatalf("error missing nameserver guidance:\n%v", err)
	}
	if remoteIssuer.called {
		t.Fatal("remote issuer should not run for ACME DNS authorization errors")
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
	err    error
	cert   acme.Certificate
}

func (r *recordingIssuer) Obtain(ctx context.Context, input acme.Input) (acme.Certificate, error) {
	r.called = true
	if r.err != nil {
		return acme.Certificate{}, r.err
	}
	if len(input.Domains) == 0 {
		return acme.Certificate{}, errors.New("domains missing")
	}
	if r.cert.CertPEM != "" || r.cert.KeyPEM != "" {
		return r.cert, nil
	}
	return acme.Certificate{CertPEM: "public-cert", KeyPEM: "public-key"}, nil
}

type recordingRemoteIssuer struct {
	called bool
	cert   acme.Certificate
	err    error
}

func (r *recordingRemoteIssuer) Obtain(ctx context.Context, remote Remote, input acme.Input) (acme.Certificate, error) {
	r.called = true
	if r.err != nil {
		return acme.Certificate{}, r.err
	}
	return r.cert, nil
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

func readFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
