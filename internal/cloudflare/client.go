package cloudflare

import (
	"context"
	"fmt"
	"strings"

	cfapi "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/accounts"
	"github.com/cloudflare/cloudflare-go/v7/dns"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/cloudflare/cloudflare-go/v7/origin_ca_certificates"
	"github.com/cloudflare/cloudflare-go/v7/shared"
	"github.com/cloudflare/cloudflare-go/v7/ssl"
	"github.com/cloudflare/cloudflare-go/v7/user"
	"github.com/cloudflare/cloudflare-go/v7/zones"
	"github.com/whitedns/wdns-wizard/pkg/types"
)

type Client interface {
	VerifyToken(ctx context.Context) error
	ListZones(ctx context.Context) ([]types.Zone, error)
	GetZoneByName(ctx context.Context, name string) (*types.Zone, error)
	EnsureDNSRecord(ctx context.Context, zoneID string, record types.DNSRecord) (*types.DNSRecordResult, error)
	SetSSLModeStrict(ctx context.Context, zoneID string) error
	CreateOriginCertificate(ctx context.Context, req types.OriginCertRequest) (*types.OriginCert, error)
}

type SDKClient struct {
	client    *cfapi.Client
	accountID string
}

func NewSDKClient(token, accountID string) *SDKClient {
	return &SDKClient{
		client:    cfapi.NewClient(option.WithAPIToken(token)),
		accountID: strings.TrimSpace(accountID),
	}
}

func (c *SDKClient) VerifyToken(ctx context.Context) error {
	if c.accountID != "" {
		res, err := c.client.Accounts.Tokens.Verify(ctx, accounts.TokenVerifyParams{
			AccountID: cfapi.F(c.accountID),
		})
		if err != nil {
			return err
		}
		if res.Status != accounts.TokenVerifyResponseStatusActive {
			return fmt.Errorf("account token status is %s", res.Status)
		}
		return nil
	}

	res, err := c.client.User.Tokens.Verify(ctx)
	if err != nil {
		return err
	}
	if res.Status != user.TokenVerifyResponseStatusActive {
		return fmt.Errorf("token status is %s", res.Status)
	}
	return nil
}

func (c *SDKClient) ListZones(ctx context.Context) ([]types.Zone, error) {
	page, err := c.client.Zones.List(ctx, zones.ZoneListParams{
		PerPage: cfapi.F(float64(50)),
	})
	if err != nil {
		return nil, err
	}
	out := make([]types.Zone, 0, len(page.Result))
	for _, zone := range page.Result {
		out = append(out, fromSDKZone(zone))
	}
	return out, nil
}

func (c *SDKClient) GetZoneByName(ctx context.Context, name string) (*types.Zone, error) {
	page, err := c.client.Zones.List(ctx, zones.ZoneListParams{
		Name:    cfapi.F(name),
		PerPage: cfapi.F(float64(10)),
	})
	if err != nil {
		return nil, err
	}
	for _, zone := range page.Result {
		if strings.EqualFold(zone.Name, name) {
			mapped := fromSDKZone(zone)
			return &mapped, nil
		}
	}
	return nil, fmt.Errorf("zone %q not found", name)
}

func (c *SDKClient) EnsureDNSRecord(ctx context.Context, zoneID string, record types.DNSRecord) (*types.DNSRecordResult, error) {
	if strings.ToUpper(record.Type) != "A" {
		return nil, fmt.Errorf("unsupported DNS record type %q", record.Type)
	}
	if record.TTL == 0 {
		record.TTL = types.DefaultTTL
	}

	existing, err := c.findDNSRecord(ctx, zoneID, record)
	if err != nil {
		return nil, err
	}
	body := dns.ARecordParam{
		Name:    cfapi.F(record.Name),
		TTL:     cfapi.F(dns.TTL(record.TTL)),
		Type:    cfapi.F(dns.ARecordTypeA),
		Content: cfapi.F(record.Content),
		Proxied: cfapi.F(record.Proxied),
	}

	if existing == nil {
		created, err := c.client.DNS.Records.New(ctx, dns.RecordNewParams{
			ZoneID: cfapi.F(zoneID),
			Body:   body,
		})
		if err != nil {
			return &types.DNSRecordResult{Record: record, Status: types.DNSRecordFailed, Error: err.Error()}, err
		}
		return &types.DNSRecordResult{Record: record, Status: types.DNSRecordCreated, ID: created.ID}, nil
	}

	if existing.Content == record.Content && existing.Proxied == record.Proxied && int(existing.TTL) == record.TTL {
		return &types.DNSRecordResult{Record: record, Status: types.DNSRecordUnchanged, ID: existing.ID}, nil
	}

	updated, err := c.client.DNS.Records.Edit(ctx, existing.ID, dns.RecordEditParams{
		ZoneID: cfapi.F(zoneID),
		Body:   body,
	})
	if err != nil {
		return &types.DNSRecordResult{Record: record, Status: types.DNSRecordFailed, ID: existing.ID, Error: err.Error()}, err
	}
	return &types.DNSRecordResult{Record: record, Status: types.DNSRecordUpdated, ID: updated.ID}, nil
}

func (c *SDKClient) SetSSLModeStrict(ctx context.Context, zoneID string) error {
	_, err := c.client.Zones.Settings.Edit(ctx, "ssl", zones.SettingEditParams{
		ZoneID: cfapi.F(zoneID),
		Body: zones.SettingEditParamsBody{
			Value: cfapi.F[interface{}](zones.SSLValueStrict),
		},
	})
	return err
}

func (c *SDKClient) CreateOriginCertificate(ctx context.Context, req types.OriginCertRequest) (*types.OriginCert, error) {
	validity := ssl.RequestValidity5475
	if req.RequestedValidity > 0 {
		validity = ssl.RequestValidity(req.RequestedValidity)
	}
	requestType := shared.CertificateRequestTypeOriginECC
	if req.RequestType != "" {
		requestType = shared.CertificateRequestType(req.RequestType)
	}
	cert, err := c.client.OriginCACertificates.New(ctx, origin_ca_certificates.OriginCACertificateNewParams{
		Csr:               cfapi.F(req.CSRPEM),
		Hostnames:         cfapi.F(req.Hostnames),
		RequestType:       cfapi.F(requestType),
		RequestedValidity: cfapi.F(validity),
	})
	if err != nil {
		return nil, err
	}
	return &types.OriginCert{
		ID:             cert.ID,
		CertificatePEM: cert.Certificate,
		ExpiresOn:      cert.ExpiresOn,
	}, nil
}

func (c *SDKClient) findDNSRecord(ctx context.Context, zoneID string, record types.DNSRecord) (*dns.RecordResponse, error) {
	page, err := c.client.DNS.Records.List(ctx, dns.RecordListParams{
		ZoneID: cfapi.F(zoneID),
		Name: cfapi.F(dns.RecordListParamsName{
			Exact: cfapi.F(record.Name),
		}),
		Type:    cfapi.F(dns.RecordListParamsTypeA),
		PerPage: cfapi.F(float64(10)),
	})
	if err != nil {
		return nil, err
	}
	for _, existing := range page.Result {
		if strings.EqualFold(existing.Name, record.Name) && string(existing.Type) == strings.ToUpper(record.Type) {
			item := existing
			return &item, nil
		}
	}
	return nil, nil
}

func fromSDKZone(zone zones.Zone) types.Zone {
	return types.Zone{
		ID:          zone.ID,
		Name:        zone.Name,
		Status:      string(zone.Status),
		NameServers: zone.NameServers,
	}
}
