package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/whitedns/wdns-wizard/internal/secrets"
	"github.com/whitedns/wdns-wizard/pkg/types"
	"gopkg.in/yaml.v3"
)

type ProjectPaths struct {
	Root            string
	ProjectDir      string
	Config          string
	Secrets         string
	CloudflareState string
	XUIState        string
	OriginCert      string
	OriginKey       string
	PublicCert      string
	PublicKey       string
	DNSPlan         string
	ProtocolPlan    string
	XUIPlan         string
	ClientLinks     string
	ClientLinksText string
	Log             string
	XUILog          string
}

func DefaultRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find user home: %w", err)
	}
	return filepath.Join(home, ".wdns-wizard", "projects"), nil
}

func Paths(root, domain string) ProjectPaths {
	projectDir := filepath.Join(root, domain)
	stamp := time.Now().UTC().Format("20060102-150405")
	return ProjectPaths{
		Root:            root,
		ProjectDir:      projectDir,
		Config:          filepath.Join(projectDir, "config.yaml"),
		Secrets:         filepath.Join(projectDir, "secrets.enc.yaml"),
		CloudflareState: filepath.Join(projectDir, "cloudflare-state.json"),
		XUIState:        filepath.Join(projectDir, "xui-state.json"),
		OriginCert:      filepath.Join(projectDir, "origin", "origin.pem"),
		OriginKey:       filepath.Join(projectDir, "origin", "origin.key"),
		PublicCert:      filepath.Join(projectDir, "certs", "public.pem"),
		PublicKey:       filepath.Join(projectDir, "certs", "public.key"),
		DNSPlan:         filepath.Join(projectDir, "plans", "dns-plan.yaml"),
		ProtocolPlan:    filepath.Join(projectDir, "plans", "protocol-plan.yaml"),
		XUIPlan:         filepath.Join(projectDir, "plans", "xui-plan.yaml"),
		ClientLinks:     filepath.Join(projectDir, "client-links.yaml"),
		ClientLinksText: filepath.Join(projectDir, "client-links.txt"),
		Log:             filepath.Join(projectDir, "logs", "provision-"+stamp+".log"),
		XUILog:          filepath.Join(projectDir, "logs", "xui-provision-"+stamp+".log"),
	}
}

func WriteProject(paths ProjectPaths, config types.ProjectConfig, state types.CloudflareState, dnsPlan types.DNSPlan, protocolPlan types.ProtocolPlan, envelope secrets.Envelope, origin types.OriginCert) error {
	for _, dir := range []string{
		paths.ProjectDir,
		filepath.Dir(paths.OriginCert),
		filepath.Dir(paths.DNSPlan),
		filepath.Dir(paths.Log),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	if err := writeYAML(paths.Config, config, 0o644); err != nil {
		return err
	}
	if err := writeYAML(paths.Secrets, envelope, 0o600); err != nil {
		return err
	}
	if err := writeJSON(paths.CloudflareState, state, 0o644); err != nil {
		return err
	}
	if err := writeYAML(paths.DNSPlan, dnsPlan, 0o644); err != nil {
		return err
	}
	if err := writeYAML(paths.ProtocolPlan, protocolPlan, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(paths.OriginCert, []byte(origin.CertificatePEM), 0o644); err != nil {
		return fmt.Errorf("write origin certificate: %w", err)
	}
	if err := os.WriteFile(paths.OriginKey, []byte(origin.PrivateKeyPEM), 0o600); err != nil {
		return fmt.Errorf("write origin private key: %w", err)
	}
	logBody := "WhiteDNS provision completed at " + time.Now().UTC().Format(time.RFC3339) + "\n"
	if err := os.WriteFile(paths.Log, []byte(logBody), 0o644); err != nil {
		return fmt.Errorf("write provision log: %w", err)
	}
	return nil
}

func WriteXUI(paths ProjectPaths, plan types.XUIPlan, state types.XUIState, links types.ClientLinks, publicCert, publicKey, logBody string) error {
	for _, dir := range []string{
		paths.ProjectDir,
		filepath.Dir(paths.XUIPlan),
		filepath.Dir(paths.XUIState),
		filepath.Dir(paths.PublicCert),
		filepath.Dir(paths.XUILog),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if err := writeYAML(paths.XUIPlan, plan, 0o644); err != nil {
		return err
	}
	if err := writeJSON(paths.XUIState, state, 0o644); err != nil {
		return err
	}
	if err := writeYAML(paths.ClientLinks, links, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(paths.ClientLinksText, []byte(RenderClientLinksText(links)), 0o600); err != nil {
		return fmt.Errorf("write client links text: %w", err)
	}
	if publicCert != "" {
		if err := os.WriteFile(paths.PublicCert, []byte(publicCert), 0o644); err != nil {
			return fmt.Errorf("write public certificate: %w", err)
		}
	}
	if publicKey != "" {
		if err := os.WriteFile(paths.PublicKey, []byte(publicKey), 0o600); err != nil {
			return fmt.Errorf("write public private key: %w", err)
		}
	}
	if logBody == "" {
		logBody = "WhiteDNS x-ui provision completed at " + time.Now().UTC().Format(time.RFC3339) + "\n"
	}
	if err := os.WriteFile(paths.XUILog, []byte(logBody), 0o644); err != nil {
		return fmt.Errorf("write xui provision log: %w", err)
	}
	return nil
}

func RenderClientLinksText(links types.ClientLinks) string {
	var b strings.Builder
	for _, client := range links.Clients {
		b.WriteString("# ")
		b.WriteString(client.Name)
		b.WriteByte('\n')
		b.WriteString(client.Link)
		b.WriteString("\n\n")
	}
	return b.String()
}

func writeYAML(path string, value interface{}, perm os.FileMode) error {
	data, err := yaml.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, value interface{}, perm os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
