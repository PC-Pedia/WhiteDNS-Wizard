package credentials

import (
	"os"
	"strings"
	"testing"
)

func TestSaveLoadCredentials(t *testing.T) {
	root := t.TempDir()
	creds := CloudflareCredentials{
		AccountID: "account-id",
		APIToken:  "api-token",
	}

	if err := Save(root, creds); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	body, err := os.ReadFile(Path(root))
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}
	if strings.Contains(string(body), "api-token") || strings.Contains(string(body), "account-id") {
		t.Fatalf("saved credentials leaked plaintext: %s", body)
	}

	got, err := Load(root)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got != creds {
		t.Fatalf("credentials = %+v, want %+v", got, creds)
	}
}

func TestLoadMissingCredentialsReturnsEmpty(t *testing.T) {
	got, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got.AccountID != "" || got.APIToken != "" {
		t.Fatalf("credentials = %+v, want empty", got)
	}
}
