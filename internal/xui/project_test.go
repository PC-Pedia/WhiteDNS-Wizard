package xui

import (
	"strings"
	"testing"
)

func TestEnsureXUISecretsBackfillsRealitySecrets(t *testing.T) {
	project := projectData{Secrets: map[string]string{}}
	changed, err := project.ensureXUISecrets(PanelCredentials{})
	if err != nil {
		t.Fatalf("ensureXUISecrets returned error: %v", err)
	}
	if !changed {
		t.Fatal("expected secrets to change")
	}
	for _, key := range []string{
		"vless_8443_uuid",
		"reality_vless_uuid",
		"reality_private_key",
		"reality_public_key",
		"reality_short_id",
		"reality_mldsa65_seed",
		"reality_mlkem_decryption",
		"reality_mlkem_encryption",
		"reality_sni",
		"hysteria2_obfs_password",
		"shadowsocks_server_password",
		"shadowsocks_client_password",
		"tor_reality_sni",
	} {
		if strings.TrimSpace(project.Secrets[key]) == "" {
			t.Fatalf("missing backfilled %s", key)
		}
	}
}
