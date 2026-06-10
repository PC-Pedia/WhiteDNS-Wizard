package cloudflare

import (
	"context"
	"fmt"
	"strings"

	"github.com/whitedns/wdns-wizard/pkg/types"
)

type ZoneLookup interface {
	GetZoneByName(ctx context.Context, name string) (*types.Zone, error)
}

func ResolveZoneForDomain(ctx context.Context, lookup ZoneLookup, domain string) (*types.Zone, error) {
	if lookup == nil {
		return nil, fmt.Errorf("Cloudflare zone lookup is not configured")
	}
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain is empty")
	}
	var closestInactive *types.Zone
	var lastErr error
	for _, candidate := range zoneCandidates(domain) {
		zone, err := lookup.GetZoneByName(ctx, candidate)
		if err != nil {
			lastErr = err
			continue
		}
		if zone == nil || !strings.EqualFold(normalizeDomain(zone.Name), candidate) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(zone.Status), "active") {
			return zone, nil
		}
		if closestInactive == nil {
			copy := *zone
			closestInactive = &copy
		}
	}
	if closestInactive != nil {
		return closestInactive, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("Cloudflare zone for %q was not found or the token cannot access it: %w", domain, lastErr)
	}
	return nil, fmt.Errorf("Cloudflare zone for %q was not found or the token cannot access it", domain)
}

func zoneCandidates(domain string) []string {
	parts := strings.Split(normalizeDomain(domain), ".")
	if len(parts) < 2 {
		return nil
	}
	out := make([]string, 0, len(parts)-1)
	for i := 0; i <= len(parts)-2; i++ {
		out = append(out, strings.Join(parts[i:], "."))
	}
	return out
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}
