package credentials

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/whitedns/wdns-wizard/internal/secrets"
	"gopkg.in/yaml.v3"
)

const CredentialsFileName = "cloudflare-credentials.enc.yaml"

type CloudflareCredentials struct {
	AccountID string `yaml:"account_id"`
	APIToken  string `yaml:"api_token"`
}

func Path(root string) string {
	return filepath.Join(root, CredentialsFileName)
}

func Load(root string) (CloudflareCredentials, error) {
	path := Path(root)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return CloudflareCredentials{}, nil
	}
	if err != nil {
		return CloudflareCredentials{}, fmt.Errorf("read saved Cloudflare credentials: %w", err)
	}

	key, err := secrets.LoadOrCreateKey(filepath.Join(root, ".secrets.key"))
	if err != nil {
		return CloudflareCredentials{}, err
	}

	var envelope secrets.Envelope
	if err := yaml.Unmarshal(data, &envelope); err != nil {
		return CloudflareCredentials{}, fmt.Errorf("read saved Cloudflare credentials: %w", err)
	}
	values, err := secrets.DecryptMap(envelope, key)
	if err != nil {
		return CloudflareCredentials{}, fmt.Errorf("decrypt saved Cloudflare credentials: %w", err)
	}
	return CloudflareCredentials{
		AccountID: values["account_id"],
		APIToken:  values["api_token"],
	}, nil
}

func Save(root string, creds CloudflareCredentials) error {
	key, err := secrets.LoadOrCreateKey(filepath.Join(root, ".secrets.key"))
	if err != nil {
		return err
	}
	envelope, err := secrets.EncryptMap(map[string]string{
		"account_id": creds.AccountID,
		"api_token":  creds.APIToken,
	}, key)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal saved Cloudflare credentials: %w", err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("create credentials directory: %w", err)
	}
	if err := os.WriteFile(Path(root), data, 0o600); err != nil {
		return fmt.Errorf("write saved Cloudflare credentials: %w", err)
	}
	return nil
}
