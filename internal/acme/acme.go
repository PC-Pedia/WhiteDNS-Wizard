package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

type Certificate struct {
	CertPEM string
	KeyPEM  string
}

type Input struct {
	Email           string
	CloudflareToken string
	Domains         []string
}

type Issuer interface {
	Obtain(ctx context.Context, input Input) (Certificate, error)
}

type LegoIssuer struct {
	CADirectoryURL string
}

var legoLoggerMu sync.Mutex

type ConnectivityError struct {
	Operation string
	Detail    string
	Cause     error
}

func (e ConnectivityError) Error() string {
	operation := strings.TrimSpace(e.Operation)
	if operation == "" {
		operation = "contacting the ACME server"
	}
	lines := []string{
		"ACME connectivity failed while " + operation + ".",
		"WhiteDNS could not reach Let's Encrypt from this machine. Check local network, firewall, DNS, proxy/VPN settings, or retry later.",
	}
	if strings.TrimSpace(e.Detail) != "" {
		lines = append(lines, "Detail: "+strings.TrimSpace(e.Detail))
	} else if e.Cause != nil {
		lines = append(lines, "Detail: "+e.Cause.Error())
	}
	return strings.Join(lines, "\n")
}

func (e ConnectivityError) Unwrap() error {
	return e.Cause
}

func IsConnectivityError(err error) bool {
	var connectivity ConnectivityError
	return errors.As(err, &connectivity)
}

func IsAuthorizationDNSError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "urn:ietf:params:acme:error:dns") ||
		strings.Contains(message, "nxdomain looking up txt") ||
		strings.Contains(message, "dns problem:")
}

const (
	cloudflareDNSPropagationTimeout = 2 * time.Minute
	cloudflareDNSPollingInterval    = 5 * time.Second
	cloudflareDNSPropagationWait    = 45 * time.Second
)

type user struct {
	email        string
	key          crypto.PrivateKey
	registration *registration.Resource
}

func (u *user) GetEmail() string {
	return u.email
}

func (u *user) GetRegistration() *registration.Resource {
	return u.registration
}

func (u *user) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func (i LegoIssuer) Obtain(ctx context.Context, input Input) (Certificate, error) {
	legoLoggerMu.Lock()
	previousLogger := legolog.Logger
	legolog.Logger = stdlog.New(io.Discard, "", 0)
	defer func() {
		legolog.Logger = previousLogger
		legoLoggerMu.Unlock()
	}()

	if strings.TrimSpace(input.CloudflareToken) == "" {
		return Certificate{}, fmt.Errorf("Cloudflare token is required for ACME DNS-01")
	}
	if len(input.Domains) == 0 {
		return Certificate{}, fmt.Errorf("at least one domain is required for ACME")
	}
	email := strings.TrimSpace(input.Email)
	if email == "" {
		email = "admin@" + strings.TrimPrefix(input.Domains[0], "direct.")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Certificate{}, fmt.Errorf("generate ACME account key: %w", err)
	}
	account := &user{email: email, key: key}
	cfg := lego.NewConfig(account)
	if i.CADirectoryURL != "" {
		cfg.CADirURL = i.CADirectoryURL
	}
	cfg.Certificate.KeyType = certcrypto.EC256
	client, err := lego.NewClient(cfg)
	if err != nil {
		if isNetworkConnectivityError(err) {
			return Certificate{}, ConnectivityError{
				Operation: "creating the ACME client",
				Detail:    err.Error(),
				Cause:     err,
			}
		}
		return Certificate{}, fmt.Errorf("create ACME client: %w", err)
	}
	providerConfig := cloudflare.NewDefaultConfig()
	providerConfig.AuthToken = strings.TrimSpace(input.CloudflareToken)
	providerConfig.ZoneToken = strings.TrimSpace(input.CloudflareToken)
	providerConfig.PropagationTimeout = cloudflareDNSPropagationTimeout
	providerConfig.PollingInterval = cloudflareDNSPollingInterval
	provider, err := cloudflare.NewDNSProviderConfig(providerConfig)
	if err != nil {
		return Certificate{}, fmt.Errorf("create Cloudflare DNS-01 provider: %w", err)
	}
	if err := client.Challenge.SetDNS01Provider(provider,
		dns01.AddRecursiveNameservers(DefaultRecursiveResolvers),
		dns01.AddDNSTimeout(5*time.Second),
		dns01.PropagationWait(cloudflareDNSPropagationWait, true),
	); err != nil {
		return Certificate{}, fmt.Errorf("configure DNS-01 challenge: %w", err)
	}
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return Certificate{}, fmt.Errorf("register ACME account: %w", err)
	}
	account.registration = reg
	type result struct {
		cert *certificate.Resource
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		cert, err := client.Certificate.Obtain(certificate.ObtainRequest{
			Domains: input.Domains,
			Bundle:  true,
		})
		ch <- result{cert: cert, err: err}
	}()
	select {
	case <-ctx.Done():
		return Certificate{}, ctx.Err()
	case got := <-ch:
		if got.err != nil {
			if isNetworkConnectivityError(got.err) {
				return Certificate{}, ConnectivityError{
					Operation: "obtaining the ACME certificate",
					Detail:    got.err.Error(),
					Cause:     got.err,
				}
			}
			return Certificate{}, fmt.Errorf("obtain ACME certificate: %w", got.err)
		}
		return Certificate{CertPEM: string(got.cert.Certificate), KeyPEM: string(got.cert.PrivateKey)}, nil
	}
}

func isNetworkConnectivityError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	message := strings.ToLower(err.Error())
	for _, needle := range []string{
		"tls handshake timeout",
		"client.timeout exceeded",
		"i/o timeout",
		"timeout awaiting response headers",
		"temporary failure in name resolution",
		"no such host",
	} {
		if strings.Contains(message, needle) {
			return true
		}
	}
	return false
}
