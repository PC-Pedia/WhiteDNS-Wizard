package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/whitedns/wdns-wizard/internal/cloudflare"
	"github.com/whitedns/wdns-wizard/internal/credentials"
	"github.com/whitedns/wdns-wizard/internal/output"
	"github.com/whitedns/wdns-wizard/internal/planner"
	"github.com/whitedns/wdns-wizard/internal/secrets"
	"github.com/whitedns/wdns-wizard/pkg/types"
)

type ClientFactory func(token, accountID string) cloudflare.Client

type Provisioner struct {
	NewClient ClientFactory
	Root      string
	AccountID string
}

func NewProvisioner(root string) Provisioner {
	return Provisioner{
		NewClient: func(token, accountID string) cloudflare.Client {
			return cloudflare.NewSDKClient(token, accountID)
		},
		Root:      root,
		AccountID: ResolveAccountID(""),
	}
}

func ResolveAccountID(accountID string) string {
	accountID = strings.TrimSpace(accountID)
	if accountID != "" {
		return accountID
	}
	return strings.TrimSpace(os.Getenv("CLOUDFLARE_ACCOUNT_ID"))
}

func (p Provisioner) Provision(ctx context.Context, input types.ProvisionInput) (types.ProvisionResult, error) {
	domain, err := planner.NormalizeDomain(input.Domain)
	if err != nil {
		return types.ProvisionResult{}, err
	}
	ip, err := planner.ValidateIPv4(input.VPSIP)
	if err != nil {
		return types.ProvisionResult{}, err
	}
	token := strings.TrimSpace(input.Token)
	if token == "" {
		return types.ProvisionResult{}, fmt.Errorf("Cloudflare API token is required")
	}
	accountID := ResolveAccountID(firstNonEmpty(input.AccountID, p.AccountID))
	if accountID == "" {
		return types.ProvisionResult{}, fmt.Errorf("Cloudflare account ID is required")
	}
	root := input.Root
	if root == "" {
		root = p.Root
	}
	if root == "" {
		root, err = output.DefaultRoot()
		if err != nil {
			return types.ProvisionResult{}, err
		}
	}

	key, err := secrets.LoadOrCreateKey(filepath.Join(root, ".secrets.key"))
	if err != nil {
		return types.ProvisionResult{}, err
	}
	generated, err := secrets.Generate()
	if err != nil {
		return types.ProvisionResult{}, err
	}
	originReq, originKey, err := cloudflare.BuildOriginCertRequest(domain)
	if err != nil {
		return types.ProvisionResult{}, err
	}

	clientFactory := p.NewClient
	if clientFactory == nil {
		clientFactory = NewProvisioner(root).NewClient
	}
	cf := clientFactory(token, accountID)
	if err := cf.VerifyToken(ctx); err != nil {
		return types.ProvisionResult{}, fmt.Errorf("verify Cloudflare token: %w", err)
	}
	if err := credentials.Save(root, credentials.CloudflareCredentials{AccountID: accountID, APIToken: token}); err != nil {
		return types.ProvisionResult{}, err
	}
	zone, err := cf.GetZoneByName(ctx, domain)
	if err != nil {
		return types.ProvisionResult{}, err
	}
	if zone.Status != "active" {
		return types.ProvisionResult{}, types.InactiveZoneError{Zone: *zone}
	}

	dnsPlan := planner.GenerateDNSPlan(domain, ip)
	protocolPlan := planner.GenerateProtocolPlan(domain, generated)
	if err := cf.SetSSLModeStrict(ctx, zone.ID); err != nil {
		return types.ProvisionResult{}, fmt.Errorf("set Cloudflare SSL mode strict: %w", err)
	}

	var dnsResults []types.DNSRecordResult
	for _, record := range dnsPlan.Records {
		result, err := cf.EnsureDNSRecord(ctx, zone.ID, record)
		if err != nil {
			if result != nil {
				dnsResults = append(dnsResults, *result)
			} else {
				dnsResults = append(dnsResults, types.DNSRecordResult{Record: record, Status: types.DNSRecordFailed, Error: err.Error()})
			}
			return types.ProvisionResult{}, fmt.Errorf("apply DNS record %s: %w", record.Name, err)
		}
		dnsResults = append(dnsResults, *result)
	}

	originCert, err := cf.CreateOriginCertificate(ctx, originReq)
	if err != nil {
		return types.ProvisionResult{}, fmt.Errorf("create Cloudflare Origin CA certificate: %w", err)
	}
	originCert.PrivateKeyPEM = originKey

	envelope, err := secrets.EncryptMap(secrets.PlaintextMap(token, generated, originKey), key)
	if err != nil {
		return types.ProvisionResult{}, err
	}

	config := types.ProjectConfig{
		Project: domain,
		ZoneID:  zone.ID,
		VPSIP:   ip,
		Cloudflare: types.CloudflareConfig{
			AccountID: accountID,
			SSLMode:   types.SSLModeStrict,
			Records:   dnsPlan.Records,
		},
	}
	state := types.CloudflareState{
		Zone:         *zone,
		DNSResults:   dnsResults,
		OriginCertID: originCert.ID,
		AppliedAt:    time.Now().UTC(),
	}
	paths := output.Paths(root, domain)
	if err := output.WriteProject(paths, config, state, dnsPlan, protocolPlan, envelope, *originCert); err != nil {
		return types.ProvisionResult{}, err
	}

	return types.ProvisionResult{
		ProjectDir:   paths.ProjectDir,
		Zone:         *zone,
		DNSResults:   dnsResults,
		OriginCert:   *originCert,
		Config:       config,
		DNSPlan:      dnsPlan,
		ProtocolPlan: protocolPlan,
	}, nil
}

func (p Provisioner) VerifyToken(ctx context.Context, token, accountID string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("Cloudflare API token is required")
	}
	accountID = ResolveAccountID(firstNonEmpty(accountID, p.AccountID))
	if accountID == "" {
		return fmt.Errorf("Cloudflare account ID is required")
	}
	clientFactory := p.NewClient
	if clientFactory == nil {
		clientFactory = NewProvisioner(p.Root).NewClient
	}
	cf := clientFactory(token, accountID)
	if err := cf.VerifyToken(ctx); err != nil {
		return fmt.Errorf("verify Cloudflare token: %w", err)
	}
	root, err := p.ResolvedRoot()
	if err != nil {
		return err
	}
	if err := credentials.Save(root, credentials.CloudflareCredentials{AccountID: accountID, APIToken: token}); err != nil {
		return err
	}
	return nil
}

func (p Provisioner) Check(ctx context.Context, token, accountID, domain string) (*types.Zone, []types.Zone, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, fmt.Errorf("Cloudflare API token is required")
	}
	accountID = ResolveAccountID(firstNonEmpty(accountID, p.AccountID))
	if accountID == "" {
		return nil, nil, fmt.Errorf("Cloudflare account ID is required")
	}
	clientFactory := p.NewClient
	if clientFactory == nil {
		clientFactory = NewProvisioner(p.Root).NewClient
	}
	cf := clientFactory(token, accountID)
	if err := cf.VerifyToken(ctx); err != nil {
		return nil, nil, fmt.Errorf("verify Cloudflare token: %w", err)
	}
	root, err := p.ResolvedRoot()
	if err != nil {
		return nil, nil, err
	}
	if err := credentials.Save(root, credentials.CloudflareCredentials{AccountID: accountID, APIToken: token}); err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(domain) != "" {
		normalized, err := planner.NormalizeDomain(domain)
		if err != nil {
			return nil, nil, err
		}
		zone, err := cf.GetZoneByName(ctx, normalized)
		return zone, nil, err
	}
	zones, err := cf.ListZones(ctx)
	return nil, zones, err
}

func (p Provisioner) LoadCredentials() (credentials.CloudflareCredentials, error) {
	root, err := p.ResolvedRoot()
	if err != nil {
		return credentials.CloudflareCredentials{}, err
	}
	return credentials.Load(root)
}

func (p Provisioner) ResolvedRoot() (string, error) {
	if strings.TrimSpace(p.Root) != "" {
		return p.Root, nil
	}
	return output.DefaultRoot()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
