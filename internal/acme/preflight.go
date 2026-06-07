package acme

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/whitedns/wdns-wizard/pkg/types"
)

type PreflightKind string

const (
	PreflightKindToken PreflightKind = "token"
	PreflightKindZone  PreflightKind = "zone"
	PreflightKindDNS   PreflightKind = "dns"
)

var DefaultRecursiveResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

type ZoneChecker interface {
	GetZoneByName(ctx context.Context, name string) (*types.Zone, error)
}

type DNSResolver interface {
	Lookup(ctx context.Context, server, name string, qtype uint16) (DNSLookupResult, error)
}

type DNSLookupResult struct {
	RCode   int
	Answers int
}

type PreflightInput struct {
	Domain      string
	ZoneChecker ZoneChecker
	Resolvers   []string
}

type PreflightChecker struct {
	Resolver DNSResolver
	Timeout  time.Duration
}

type PreflightError struct {
	Kind        PreflightKind
	Domain      string
	Detail      string
	NameServers []string
	Cause       error
}

func (e PreflightError) Error() string {
	domain := strings.TrimSpace(e.Domain)
	if domain == "" {
		domain = "<domain>"
	}
	lines := []string{
		fmt.Sprintf("ACME DNS preflight failed for %s.", domain),
		fmt.Sprintf("WhiteDNS could not verify _acme-challenge.%s through public DNS.", domain),
		"Check that the domain is active in Cloudflare, registrar nameservers point to Cloudflare, and the API token is scoped to this zone.",
	}
	if strings.TrimSpace(e.Detail) != "" {
		lines = append(lines, "Detail: "+strings.TrimSpace(e.Detail))
	}
	if len(e.NameServers) > 0 {
		lines = append(lines, "Cloudflare nameservers: "+strings.Join(e.NameServers, ", "))
	}
	return strings.Join(lines, "\n")
}

func (e PreflightError) Unwrap() error {
	return e.Cause
}

func IsTokenPreflightError(err error) bool {
	var preflight PreflightError
	return errors.As(err, &preflight) && preflight.Kind == PreflightKindToken
}

func IsZoneOrDNSPreflightError(err error) bool {
	var preflight PreflightError
	return errors.As(err, &preflight) && (preflight.Kind == PreflightKindZone || preflight.Kind == PreflightKindDNS)
}

func (c PreflightChecker) Check(ctx context.Context, input PreflightInput) error {
	domain := normalizeDomain(input.Domain)
	if domain == "" {
		return PreflightError{Kind: PreflightKindZone, Domain: input.Domain, Detail: "domain is empty"}
	}
	if input.ZoneChecker == nil {
		return PreflightError{Kind: PreflightKindToken, Domain: domain, Detail: "Cloudflare zone checker is not configured"}
	}
	zone, err := input.ZoneChecker.GetZoneByName(ctx, domain)
	if err != nil {
		return PreflightError{
			Kind:   PreflightKindToken,
			Domain: domain,
			Detail: fmt.Sprintf("Cloudflare zone %q was not found or the token cannot access it", domain),
			Cause:  err,
		}
	}
	if zone == nil {
		return PreflightError{Kind: PreflightKindToken, Domain: domain, Detail: fmt.Sprintf("Cloudflare zone %q was not found or the token cannot access it", domain)}
	}
	if !strings.EqualFold(strings.TrimSpace(zone.Status), "active") {
		return PreflightError{
			Kind:        PreflightKindZone,
			Domain:      domain,
			Detail:      fmt.Sprintf("Cloudflare zone status is %q, not active", zone.Status),
			NameServers: zone.NameServers,
		}
	}

	resolvers := input.Resolvers
	if len(resolvers) == 0 {
		resolvers = DefaultRecursiveResolvers
	}
	resolver := c.Resolver
	if resolver == nil {
		resolver = DNSClientResolver{Timeout: c.Timeout}
	}
	for _, check := range []struct {
		name  string
		qtype uint16
	}{
		{name: domain, qtype: dns.TypeNS},
		{name: domain, qtype: dns.TypeSOA},
	} {
		if err := requirePublicDNSAnswers(ctx, resolver, resolvers, check.name, check.qtype); err != nil {
			return PreflightError{Kind: PreflightKindDNS, Domain: domain, Detail: err.Error(), Cause: err}
		}
	}
	if err := requireChallengeSOAReachable(ctx, resolver, resolvers, "_acme-challenge."+domain); err != nil {
		return PreflightError{Kind: PreflightKindDNS, Domain: domain, Detail: err.Error(), Cause: err}
	}
	return nil
}

type DNSClientResolver struct {
	Timeout time.Duration
}

func (r DNSClientResolver) Lookup(ctx context.Context, server, name string, qtype uint16) (DNSLookupResult, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := &dns.Client{Net: "udp", Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	resp, _, err := client.ExchangeContext(ctx, msg, server)
	if err != nil {
		return DNSLookupResult{}, err
	}
	if resp == nil {
		return DNSLookupResult{}, fmt.Errorf("empty DNS response")
	}
	return DNSLookupResult{RCode: resp.Rcode, Answers: len(resp.Answer)}, nil
}

func requirePublicDNSAnswers(ctx context.Context, resolver DNSResolver, resolvers []string, name string, qtype uint16) error {
	var details []string
	for _, server := range resolvers {
		result, err := resolver.Lookup(ctx, server, name, qtype)
		if err != nil {
			details = append(details, fmt.Sprintf("%s %s @%s failed: %v", dns.TypeToString[qtype], dns.Fqdn(name), server, err))
			continue
		}
		if result.RCode != dns.RcodeSuccess {
			details = append(details, fmt.Sprintf("%s %s @%s returned %s", dns.TypeToString[qtype], dns.Fqdn(name), server, dns.RcodeToString[result.RCode]))
			continue
		}
		if result.Answers == 0 {
			details = append(details, fmt.Sprintf("%s %s @%s returned no answers", dns.TypeToString[qtype], dns.Fqdn(name), server))
			continue
		}
		return nil
	}
	return errors.New(strings.Join(details, "; "))
}

func requireChallengeSOAReachable(ctx context.Context, resolver DNSResolver, resolvers []string, name string) error {
	var details []string
	for _, server := range resolvers {
		result, err := resolver.Lookup(ctx, server, name, dns.TypeSOA)
		if err != nil {
			details = append(details, fmt.Sprintf("SOA %s @%s failed: %v", dns.Fqdn(name), server, err))
			continue
		}
		if result.RCode == dns.RcodeSuccess || result.RCode == dns.RcodeNameError {
			return nil
		}
		details = append(details, fmt.Sprintf("SOA %s @%s returned %s", dns.Fqdn(name), server, dns.RcodeToString[result.RCode]))
	}
	return errors.New(strings.Join(details, "; "))
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}
