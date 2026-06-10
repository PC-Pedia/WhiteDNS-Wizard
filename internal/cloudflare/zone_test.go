package cloudflare

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/whitedns/wdns-wizard/pkg/types"
)

type fakeZoneLookup struct {
	zones map[string]types.Zone
	calls []string
}

func (f *fakeZoneLookup) GetZoneByName(ctx context.Context, name string) (*types.Zone, error) {
	f.calls = append(f.calls, name)
	zone, ok := f.zones[normalizeDomain(name)]
	if !ok {
		return nil, fmt.Errorf("zone %q not found", name)
	}
	return &zone, nil
}

func TestResolveZoneForDomainUsesParentZoneForSubdomain(t *testing.T) {
	lookup := &fakeZoneLookup{zones: map[string]types.Zone{
		"example.com": {ID: "zone-parent", Name: "example.com", Status: "active"},
	}}

	zone, err := ResolveZoneForDomain(context.Background(), lookup, "vpn.example.com")
	if err != nil {
		t.Fatalf("ResolveZoneForDomain returned error: %v", err)
	}
	if zone.ID != "zone-parent" || zone.Name != "example.com" {
		t.Fatalf("zone = %+v, want parent example.com", zone)
	}
	wantCalls := []string{"vpn.example.com", "example.com"}
	if !reflect.DeepEqual(lookup.calls, wantCalls) {
		t.Fatalf("calls = %+v, want %+v", lookup.calls, wantCalls)
	}
}

func TestResolveZoneForDomainPrefersActiveParentOverInactiveChild(t *testing.T) {
	lookup := &fakeZoneLookup{zones: map[string]types.Zone{
		"vpn.example.com": {ID: "zone-child", Name: "vpn.example.com", Status: "pending"},
		"example.com":     {ID: "zone-parent", Name: "example.com", Status: "active"},
	}}

	zone, err := ResolveZoneForDomain(context.Background(), lookup, "vpn.example.com")
	if err != nil {
		t.Fatalf("ResolveZoneForDomain returned error: %v", err)
	}
	if zone.ID != "zone-parent" {
		t.Fatalf("zone = %+v, want active parent", zone)
	}
}

func TestResolveZoneForDomainReturnsInactiveZoneWhenNoActiveZoneExists(t *testing.T) {
	lookup := &fakeZoneLookup{zones: map[string]types.Zone{
		"example.com": {ID: "zone-id", Name: "example.com", Status: "pending"},
	}}

	zone, err := ResolveZoneForDomain(context.Background(), lookup, "example.com")
	if err != nil {
		t.Fatalf("ResolveZoneForDomain returned error: %v", err)
	}
	if zone.ID != "zone-id" || zone.Status != "pending" {
		t.Fatalf("zone = %+v, want inactive exact zone", zone)
	}
}
