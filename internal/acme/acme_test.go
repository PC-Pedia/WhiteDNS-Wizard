package acme

import (
	"context"
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
	if cloudflareDNSPropagationTimeout != 10*time.Minute {
		t.Fatalf("propagation timeout = %s, want 10m", cloudflareDNSPropagationTimeout)
	}
	if cloudflareDNSPollingInterval != 5*time.Second {
		t.Fatalf("polling interval = %s, want 5s", cloudflareDNSPollingInterval)
	}
}
