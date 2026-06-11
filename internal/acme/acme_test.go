package acme

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLegoIssuerRejectsMissingCloudflareToken(t *testing.T) {
	_, err := (LegoIssuer{}).Obtain(context.Background(), Input{
		Email:   "admin@example.com",
		Domains: []string{"direct.example.com"},
	})
	if err == nil {
		t.Fatal("expected missing token error")
	}
	if !strings.Contains(err.Error(), "Cloudflare token is required") {
		t.Fatalf("error = %v", err)
	}
}

func TestCloudflareDNSPropagationWaitIsTolerant(t *testing.T) {
	if cloudflareDNSPropagationTimeout != 2*time.Minute {
		t.Fatalf("propagation timeout = %s, want 2m", cloudflareDNSPropagationTimeout)
	}
	if cloudflareDNSPollingInterval != 5*time.Second {
		t.Fatalf("polling interval = %s, want 5s", cloudflareDNSPollingInterval)
	}
	if cloudflareDNSPropagationWait != 45*time.Second {
		t.Fatalf("propagation wait = %s, want 45s", cloudflareDNSPropagationWait)
	}
}

func TestConnectivityErrorMatchesTLSHandshakeTimeout(t *testing.T) {
	err := &url.Error{
		Op:  "Get",
		URL: "https://acme-v02.api.letsencrypt.org/directory",
		Err: errors.New("net/http: TLS handshake timeout"),
	}
	if !isNetworkConnectivityError(err) {
		t.Fatalf("isNetworkConnectivityError(%v) = false, want true", err)
	}

	wrapped := ConnectivityError{
		Operation: "creating the ACME client",
		Cause:     err,
	}
	if !IsConnectivityError(wrapped) {
		t.Fatalf("IsConnectivityError(%T) = false, want true", wrapped)
	}
	for _, want := range []string{"ACME connectivity failed", "Let's Encrypt", "TLS handshake timeout"} {
		if !strings.Contains(wrapped.Error(), want) {
			t.Fatalf("ConnectivityError missing %q:\n%s", want, wrapped.Error())
		}
	}
}

func TestConnectivityErrorMatchesNetTimeout(t *testing.T) {
	if !isNetworkConnectivityError(timeoutError{}) {
		t.Fatal("net timeout error should be classified as ACME connectivity")
	}
	if isNetworkConnectivityError(errors.New("unauthorized account")) {
		t.Fatal("non-network error should not be classified as ACME connectivity")
	}
}

func TestConnectivityErrorMatchesDNSCallTimeoutDuringChallengePresentation(t *testing.T) {
	err := errors.New(`error: one or more domains had a problem:
[*.cityrouds.sbs] acme: error presenting token: cloudflare: could not find zone for domain "cityrouds.sbs": [fqdn=_acme-challenge.cityrouds.sbs.] could not find the start of authority for '_acme-challenge.cityrouds.sbs.': DNS call error: read udp 192.168.1.100:53107->216.239.38.120:53: i/o timeout`)
	if !isNetworkConnectivityError(err) {
		t.Fatalf("isNetworkConnectivityError(%v) = false, want true", err)
	}
}

func TestAuthorizationDNSErrorMatchesNXDOMAINLookingUpTXT(t *testing.T) {
	err := errors.New(`obtain ACME certificate: error: one or more domains had a problem:
[*.cityrouds.sbs] invalid authorization: acme: error: 400 :: urn:ietf:params:acme:error:dns :: DNS problem: NXDOMAIN looking up TXT for _acme-challenge.cityrouds.sbs - check that a DNS record exists for this domain`)
	if !IsAuthorizationDNSError(err) {
		t.Fatalf("IsAuthorizationDNSError(%v) = false, want true", err)
	}
	if IsAuthorizationDNSError(errors.New("register ACME account: unauthorized")) {
		t.Fatal("non-DNS authorization error should not be classified as DNS authorization")
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
