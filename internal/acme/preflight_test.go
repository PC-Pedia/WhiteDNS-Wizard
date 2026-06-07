package acme

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/whitedns/wdns-wizard/pkg/types"
)

type fakeZoneChecker struct {
	zone *types.Zone
	err  error
}

func (f fakeZoneChecker) GetZoneByName(ctx context.Context, name string) (*types.Zone, error) {
	return f.zone, f.err
}

type fakeDNSResolver struct {
	results map[string]DNSLookupResult
	errs    map[string]error
}

func (f fakeDNSResolver) Lookup(ctx context.Context, server, name string, qtype uint16) (DNSLookupResult, error) {
	key := server + "|" + dns.TypeToString[qtype] + "|" + dns.Fqdn(name)
	if err := f.errs[key]; err != nil {
		return DNSLookupResult{}, err
	}
	if result, ok := f.results[key]; ok {
		return result, nil
	}
	return DNSLookupResult{RCode: dns.RcodeSuccess, Answers: 1}, nil
}

func TestPreflightCheckerPassesForActiveZoneAndPublicDNS(t *testing.T) {
	err := (PreflightChecker{Resolver: fakeDNSResolver{}}).Check(context.Background(), PreflightInput{
		Domain: "Example.COM.",
		ZoneChecker: fakeZoneChecker{zone: &types.Zone{
			Name:   "example.com",
			Status: "active",
		}},
		Resolvers: []string{"1.1.1.1:53"},
	})
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
}

func TestPreflightCheckerFailsWhenZoneIsNotAccessible(t *testing.T) {
	err := (PreflightChecker{Resolver: fakeDNSResolver{}}).Check(context.Background(), PreflightInput{
		Domain:      "example.com",
		ZoneChecker: fakeZoneChecker{err: errors.New("zone not found")},
		Resolvers:   []string{"1.1.1.1:53"},
	})
	if !IsTokenPreflightError(err) {
		t.Fatalf("error = %T %[1]v, want token preflight error", err)
	}
	if !strings.Contains(err.Error(), "token cannot access") {
		t.Fatalf("error missing token guidance:\n%v", err)
	}
}

func TestPreflightCheckerFailsWhenZoneIsInactive(t *testing.T) {
	err := (PreflightChecker{Resolver: fakeDNSResolver{}}).Check(context.Background(), PreflightInput{
		Domain: "example.com",
		ZoneChecker: fakeZoneChecker{zone: &types.Zone{
			Name:        "example.com",
			Status:      "pending",
			NameServers: []string{"newt.ns.cloudflare.com", "sofia.ns.cloudflare.com"},
		}},
		Resolvers: []string{"1.1.1.1:53"},
	})
	if !IsZoneOrDNSPreflightError(err) {
		t.Fatalf("error = %T %[1]v, want zone preflight error", err)
	}
	for _, want := range []string{"status is \"pending\"", "newt.ns.cloudflare.com", "sofia.ns.cloudflare.com"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q:\n%v", want, err)
		}
	}
}

func TestPreflightCheckerFailsOnRefusedAcmeSOA(t *testing.T) {
	resolver := fakeDNSResolver{
		results: map[string]DNSLookupResult{
			"1.1.1.1:53|SOA|_acme-challenge.example.com.": {RCode: dns.RcodeRefused},
		},
	}
	err := (PreflightChecker{Resolver: resolver}).Check(context.Background(), PreflightInput{
		Domain: "example.com",
		ZoneChecker: fakeZoneChecker{zone: &types.Zone{
			Name:   "example.com",
			Status: "active",
		}},
		Resolvers: []string{"1.1.1.1:53"},
	})
	if !IsZoneOrDNSPreflightError(err) {
		t.Fatalf("error = %T %[1]v, want DNS preflight error", err)
	}
	for _, want := range []string{"SOA _acme-challenge.example.com. @1.1.1.1:53 returned REFUSED", "ACME DNS preflight failed for example.com"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q:\n%v", want, err)
		}
	}
}

func TestPreflightCheckerAcceptsNXDOMAINForMissingAcmeChallengeSOA(t *testing.T) {
	resolver := fakeDNSResolver{
		results: map[string]DNSLookupResult{
			"1.1.1.1:53|SOA|_acme-challenge.example.com.": {RCode: dns.RcodeNameError},
		},
	}
	err := (PreflightChecker{Resolver: resolver}).Check(context.Background(), PreflightInput{
		Domain: "example.com",
		ZoneChecker: fakeZoneChecker{zone: &types.Zone{
			Name:   "example.com",
			Status: "active",
		}},
		Resolvers: []string{"1.1.1.1:53"},
	})
	if err != nil {
		t.Fatalf("Check returned error for normal missing challenge label: %v", err)
	}
}

func TestPreflightCheckerFailsOnMissingNSAnswers(t *testing.T) {
	resolver := fakeDNSResolver{
		results: map[string]DNSLookupResult{
			"1.1.1.1:53|NS|example.com.": {RCode: dns.RcodeSuccess, Answers: 0},
		},
	}
	err := (PreflightChecker{Resolver: resolver}).Check(context.Background(), PreflightInput{
		Domain: "example.com",
		ZoneChecker: fakeZoneChecker{zone: &types.Zone{
			Name:   "example.com",
			Status: "active",
		}},
		Resolvers: []string{"1.1.1.1:53"},
	})
	if !IsZoneOrDNSPreflightError(err) {
		t.Fatalf("error = %T %[1]v, want DNS preflight error", err)
	}
	if !strings.Contains(err.Error(), "NS example.com. @1.1.1.1:53 returned no answers") {
		t.Fatalf("error missing NS detail:\n%v", err)
	}
}
