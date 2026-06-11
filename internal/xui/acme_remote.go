package xui

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/whitedns/wdns-wizard/internal/acme"
)

const (
	remoteLegoImage                      = "goacme/lego:v4.24.0"
	remoteACMEPropagationTimeoutSeconds  = 180
	remoteACMEPollingIntervalSeconds     = 5
	remoteACMEPropagationWait            = "45s"
	remoteACMEHTTPTimeoutSeconds         = 30
	remoteACMEDNSTimeoutSeconds          = 5
	remoteACMERecursiveResolverPrimary   = "1.1.1.1:53"
	remoteACMERecursiveResolverSecondary = "8.8.8.8:53"
	remoteACMEContainerWorkDir           = "/data"
	remoteACMEIssueTimeout               = 5 * time.Minute
)

type ACMERemoteIssuer interface {
	Obtain(ctx context.Context, remote Remote, input acme.Input) (acme.Certificate, error)
}

type RemoteLegoIssuer struct {
	Image string
	Now   func() time.Time
}

type ACMEFallbackError struct {
	Local  error
	Remote error
}

func (e ACMEFallbackError) Error() string {
	lines := []string{
		"Local ACME could not reach Let's Encrypt, and the VPS fallback also failed.",
		"Press Y to retry 3x-ui apply after checking that the VPS can reach Let's Encrypt and Cloudflare, and that Docker or lego is available.",
	}
	if e.Local != nil {
		lines = append(lines, "Local detail: "+oneLine(e.Local.Error()))
	}
	if e.Remote != nil {
		lines = append(lines, "VPS detail: "+oneLine(e.Remote.Error()))
	}
	return strings.Join(lines, "\n")
}

func (e ACMEFallbackError) Unwrap() error {
	return e.Remote
}

func (i RemoteLegoIssuer) Obtain(ctx context.Context, remote Remote, input acme.Input) (acme.Certificate, error) {
	if remote == nil {
		return acme.Certificate{}, fmt.Errorf("remote ACME issuer requires an active SSH connection")
	}
	token := strings.TrimSpace(input.CloudflareToken)
	if token == "" {
		return acme.Certificate{}, fmt.Errorf("Cloudflare token is required for remote ACME DNS-01")
	}
	if strings.ContainsAny(token, "\r\n") {
		return acme.Certificate{}, fmt.Errorf("Cloudflare token contains invalid newline characters")
	}
	if len(input.Domains) == 0 || strings.TrimSpace(input.Domains[0]) == "" {
		return acme.Certificate{}, fmt.Errorf("at least one domain is required for remote ACME")
	}
	domain := strings.TrimSpace(input.Domains[0])
	email := strings.TrimSpace(input.Email)
	if email == "" {
		email = "admin@" + strings.TrimPrefix(domain, "*.")
	}

	now := time.Now
	if i.Now != nil {
		now = i.Now
	}
	certBase := remoteLegoCertBaseName(domain)
	suffix := now().UTC().UnixNano()
	workDir := fmt.Sprintf("/tmp/wdns-acme-%s-%d", remotePathComponent(certBase), suffix)
	envPath := workDir + ".env"
	image := strings.TrimSpace(i.Image)
	if image == "" {
		image = remoteLegoImage
	}

	env := remoteLegoEnvFile(token)
	if err := remote.Upload(ctx, envPath, []byte(env), 0o600); err != nil {
		return acme.Certificate{}, fmt.Errorf("upload remote ACME environment: %w", err)
	}
	defer cleanupRemoteACME(ctx, remote, workDir, envPath)

	if _, err := remote.Run(ctx, remoteLegoRunCommand(workDir, envPath, email, domain, certBase, image)); err != nil {
		return acme.Certificate{}, fmt.Errorf("run remote ACME issuance: %w", err)
	}

	certPEM, err := remote.Run(ctx, "cat "+shQuote(workDir+"/certificates/"+certBase+".crt"))
	if err != nil {
		return acme.Certificate{}, fmt.Errorf("read remote ACME certificate: %w", err)
	}
	keyPEM, err := remote.Run(ctx, "cat "+shQuote(workDir+"/certificates/"+certBase+".key"))
	if err != nil {
		return acme.Certificate{}, fmt.Errorf("read remote ACME private key: %w", err)
	}
	cert := acme.Certificate{
		CertPEM: strings.TrimSpace(certPEM) + "\n",
		KeyPEM:  strings.TrimSpace(keyPEM) + "\n",
	}
	if err := validateCertificatePair(cert); err != nil {
		return acme.Certificate{}, fmt.Errorf("validate remote ACME certificate: %w", err)
	}
	return cert, nil
}

func remoteLegoEnvFile(token string) string {
	return strings.Join([]string{
		"CLOUDFLARE_DNS_API_TOKEN=" + token,
		"CLOUDFLARE_ZONE_API_TOKEN=" + token,
		fmt.Sprintf("CLOUDFLARE_PROPAGATION_TIMEOUT=%d", remoteACMEPropagationTimeoutSeconds),
		fmt.Sprintf("CLOUDFLARE_POLLING_INTERVAL=%d", remoteACMEPollingIntervalSeconds),
		fmt.Sprintf("CLOUDFLARE_HTTP_TIMEOUT=%d", remoteACMEHTTPTimeoutSeconds),
		"",
	}, "\n")
}

func remoteLegoRunCommand(workDir, envPath, email, domain, certBase, image string) string {
	script := "set -eu\n" +
		"work_dir=" + shQuote(workDir) + "\n" +
		"env_file=" + shQuote(envPath) + "\n" +
		"email=" + shQuote(email) + "\n" +
		"domain=" + shQuote(domain) + "\n" +
		"cert_base=" + shQuote(certBase) + "\n" +
		"image=" + shQuote(image) + "\n" +
		"mkdir -p \"$work_dir\"\n" +
		"chmod 700 \"$work_dir\"\n" +
		"if command -v lego >/dev/null 2>&1; then\n" +
		"  token=\"$(sed -n 's/^CLOUDFLARE_DNS_API_TOKEN=//p' \"$env_file\" | head -n 1)\"\n" +
		"  zone_token=\"$(sed -n 's/^CLOUDFLARE_ZONE_API_TOKEN=//p' \"$env_file\" | head -n 1)\"\n" +
		"  export CLOUDFLARE_DNS_API_TOKEN=\"$token\"\n" +
		"  export CLOUDFLARE_ZONE_API_TOKEN=\"$zone_token\"\n" +
		fmt.Sprintf("  export CLOUDFLARE_PROPAGATION_TIMEOUT=%d\n", remoteACMEPropagationTimeoutSeconds) +
		fmt.Sprintf("  export CLOUDFLARE_POLLING_INTERVAL=%d\n", remoteACMEPollingIntervalSeconds) +
		fmt.Sprintf("  export CLOUDFLARE_HTTP_TIMEOUT=%d\n", remoteACMEHTTPTimeoutSeconds) +
		"  lego --accept-tos --email \"$email\" --dns cloudflare --domains \"$domain\" --key-type ec256 --dns-timeout " + fmt.Sprintf("%d", remoteACMEDNSTimeoutSeconds) + " --dns.resolvers " + shQuoteArg(remoteACMERecursiveResolverPrimary) + " --dns.resolvers " + shQuoteArg(remoteACMERecursiveResolverSecondary) + " --dns.propagation-wait " + shQuoteArg(remoteACMEPropagationWait) + " --path \"$work_dir\" run\n" +
		"else\n" +
		"  docker run --rm --env-file \"$env_file\" -v \"$work_dir:" + remoteACMEContainerWorkDir + "\" \"$image\" --accept-tos --email \"$email\" --dns cloudflare --domains \"$domain\" --key-type ec256 --dns-timeout " + fmt.Sprintf("%d", remoteACMEDNSTimeoutSeconds) + " --dns.resolvers " + shQuoteArg(remoteACMERecursiveResolverPrimary) + " --dns.resolvers " + shQuoteArg(remoteACMERecursiveResolverSecondary) + " --dns.propagation-wait " + shQuoteArg(remoteACMEPropagationWait) + " --path " + remoteACMEContainerWorkDir + " run\n" +
		"fi\n" +
		"test -s \"$work_dir/certificates/$cert_base.crt\"\n" +
		"test -s \"$work_dir/certificates/$cert_base.key\""
	return "sh -lc " + shQuote(script)
}

func cleanupRemoteACME(ctx context.Context, remote Remote, workDir, envPath string) {
	cleanupCtx := ctx
	if cleanupCtx == nil || cleanupCtx.Err() != nil {
		cleanupCtx = context.Background()
	}
	cleanupCtx, cancel := context.WithTimeout(cleanupCtx, 30*time.Second)
	defer cancel()
	_, _ = remote.Run(cleanupCtx, "rm -rf "+shQuote(workDir)+" "+shQuote(envPath))
}

func remoteLegoCertBaseName(domain string) string {
	return strings.NewReplacer(":", "-", "*", "_").Replace(strings.TrimSpace(domain))
}

func remotePathComponent(value string) string {
	var b strings.Builder
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	out := strings.Trim(b.String(), ".-")
	if out == "" {
		return "cert"
	}
	return out
}

func validateCertificatePair(cert acme.Certificate) error {
	if strings.TrimSpace(cert.CertPEM) == "" {
		return fmt.Errorf("certificate PEM is empty")
	}
	if strings.TrimSpace(cert.KeyPEM) == "" {
		return fmt.Errorf("private key PEM is empty")
	}
	if _, err := tls.X509KeyPair([]byte(cert.CertPEM), []byte(cert.KeyPEM)); err != nil {
		return err
	}
	return nil
}
