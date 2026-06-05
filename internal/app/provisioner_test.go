package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whitedns/wdns-wizard/internal/cloudflare"
	"github.com/whitedns/wdns-wizard/pkg/types"
)

type fakeCloudflare struct {
	zone       types.Zone
	records    map[string]types.DNSRecord
	verified   bool
	setSSL     int
	certCreate int
}

func (f *fakeCloudflare) VerifyToken(ctx context.Context) error {
	f.verified = true
	return nil
}

func (f *fakeCloudflare) ListZones(ctx context.Context) ([]types.Zone, error) {
	return []types.Zone{f.zone}, nil
}

func (f *fakeCloudflare) GetZoneByName(ctx context.Context, name string) (*types.Zone, error) {
	return &f.zone, nil
}

func (f *fakeCloudflare) EnsureDNSRecord(ctx context.Context, zoneID string, record types.DNSRecord) (*types.DNSRecordResult, error) {
	if f.records == nil {
		f.records = map[string]types.DNSRecord{}
	}
	existing, ok := f.records[record.Name]
	if !ok {
		f.records[record.Name] = record
		return &types.DNSRecordResult{Record: record, Status: types.DNSRecordCreated, ID: "new-" + record.Name}, nil
	}
	if existing.Content == record.Content && existing.Proxied == record.Proxied {
		return &types.DNSRecordResult{Record: record, Status: types.DNSRecordUnchanged, ID: "existing-" + record.Name}, nil
	}
	f.records[record.Name] = record
	return &types.DNSRecordResult{Record: record, Status: types.DNSRecordUpdated, ID: "existing-" + record.Name}, nil
}

func (f *fakeCloudflare) SetSSLModeStrict(ctx context.Context, zoneID string) error {
	f.setSSL++
	return nil
}

func (f *fakeCloudflare) CreateOriginCertificate(ctx context.Context, req types.OriginCertRequest) (*types.OriginCert, error) {
	f.certCreate++
	return &types.OriginCert{ID: "cert-id", CertificatePEM: "cert"}, nil
}

func TestProvisionWritesProject(t *testing.T) {
	root := t.TempDir()
	fake := &fakeCloudflare{
		zone: types.Zone{ID: "zone-id", Name: "example.com", Status: "active"},
	}
	provisioner := Provisioner{
		Root: root,
		NewClient: func(token, accountID string) cloudflare.Client {
			if token != "token" {
				t.Fatalf("token = %q", token)
			}
			if accountID != "account-id" {
				t.Fatalf("accountID = %q", accountID)
			}
			return fake
		},
	}

	result, err := provisioner.Provision(context.Background(), types.ProvisionInput{
		Token:     "token",
		AccountID: "account-id",
		Domain:    "example.com",
		VPSIP:     "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("Provision returned error: %v", err)
	}
	if result.Config.Cloudflare.SSLMode != types.SSLModeStrict {
		t.Fatalf("ssl mode = %q", result.Config.Cloudflare.SSLMode)
	}
	if fake.setSSL != 1 || fake.certCreate != 1 {
		t.Fatalf("mutations setSSL=%d certCreate=%d", fake.setSSL, fake.certCreate)
	}
	configBody, err := os.ReadFile(filepath.Join(root, "example.com", "config.yaml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(configBody) == "" || strings.Contains(string(configBody), "token") {
		t.Fatalf("config leaked token or was empty: %s", configBody)
	}
	if _, err := os.Stat(filepath.Join(root, "example.com", "origin", "origin.key")); err != nil {
		t.Fatalf("origin key missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".secrets.key")); err != nil {
		t.Fatalf("generated secrets key missing: %v", err)
	}
}

func TestProvisionStopsWhenZoneInactive(t *testing.T) {
	fake := &fakeCloudflare{
		zone: types.Zone{ID: "zone-id", Name: "example.com", Status: "pending", NameServers: []string{"a.ns.cloudflare.com"}},
	}
	provisioner := Provisioner{
		Root: t.TempDir(),
		NewClient: func(token, accountID string) cloudflare.Client {
			return fake
		},
	}
	_, err := provisioner.Provision(context.Background(), types.ProvisionInput{
		Token:     "token",
		AccountID: "account-id",
		Domain:    "example.com",
		VPSIP:     "1.2.3.4",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(types.InactiveZoneError); !ok {
		t.Fatalf("error type = %T, want InactiveZoneError", err)
	}
	if fake.setSSL != 0 || fake.certCreate != 0 || len(fake.records) != 0 {
		t.Fatalf("unexpected mutations on inactive zone")
	}
}

func TestProvisionRequiresAccountID(t *testing.T) {
	provisioner := Provisioner{
		Root: t.TempDir(),
		NewClient: func(token, accountID string) cloudflare.Client {
			t.Fatal("client should not be created")
			return nil
		},
	}
	_, err := provisioner.Provision(context.Background(), types.ProvisionInput{
		Token:  "token",
		Domain: "example.com",
		VPSIP:  "1.2.3.4",
	})
	if err == nil || !strings.Contains(err.Error(), "account ID") {
		t.Fatalf("expected account ID error, got %v", err)
	}
}
