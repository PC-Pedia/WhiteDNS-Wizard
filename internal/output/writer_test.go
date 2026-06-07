package output

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/whitedns/wdns-wizard/internal/secrets"
	"github.com/whitedns/wdns-wizard/pkg/types"
)

func TestPaths(t *testing.T) {
	paths := Paths("/tmp/root", "example.com")
	if paths.ProjectDir != filepath.Join("/tmp/root", "example.com") {
		t.Fatalf("ProjectDir = %q", paths.ProjectDir)
	}
	if paths.OriginKey != filepath.Join("/tmp/root", "example.com", "origin", "origin.key") {
		t.Fatalf("OriginKey = %q", paths.OriginKey)
	}
	if paths.ClientLinksText != filepath.Join("/tmp/root", "example.com", "client-links.txt") {
		t.Fatalf("ClientLinksText = %q", paths.ClientLinksText)
	}
}

func TestWriteProjectPermissions(t *testing.T) {
	root := t.TempDir()
	paths := Paths(root, "example.com")
	config := types.ProjectConfig{
		Project: "example.com",
		ZoneID:  "zone-id",
		VPSIP:   "1.2.3.4",
		Cloudflare: types.CloudflareConfig{
			SSLMode: types.SSLModeStrict,
		},
	}
	state := types.CloudflareState{
		Zone:      types.Zone{ID: "zone-id", Name: "example.com", Status: "active"},
		AppliedAt: time.Now(),
	}
	envelope := secrets.Envelope{
		Version:    1,
		Algorithm:  "XCHACHA20-POLY1305",
		Nonce:      "nonce",
		Ciphertext: "ciphertext",
		CreatedAt:  time.Now().Format(time.RFC3339),
	}
	origin := types.OriginCert{
		CertificatePEM: "cert",
		PrivateKeyPEM:  "key",
	}
	if err := WriteProject(paths, config, state, types.DNSPlan{}, types.ProtocolPlan{}, envelope, origin); err != nil {
		t.Fatalf("WriteProject returned error: %v", err)
	}
	assertPerm(t, paths.Secrets, 0o600)
	assertPerm(t, paths.OriginKey, 0o600)
	assertPerm(t, paths.Config, 0o644)
}

func TestWriteXUIWritesPlainClientLinks(t *testing.T) {
	root := t.TempDir()
	paths := Paths(root, "example.com")
	links := types.ClientLinks{Clients: []types.ClientLink{
		{Name: "VLESS WS @whiteDNS", Link: "vless://uuid@vpn.example.com:443?type=ws&security=tls#VLESS%20WS%20%40whiteDNS"},
		{Name: "Reality TCP Vision @whiteDNS", Link: "vless://uuid@reality.example.com:2083?type=tcp&security=reality&flow=xtls-rprx-vision#Reality%20TCP%20Vision%20%40whiteDNS"},
	}}

	if err := WriteXUI(paths, types.XUIPlan{}, types.XUIState{}, links, "", "", ""); err != nil {
		t.Fatalf("WriteXUI returned error: %v", err)
	}
	data, err := os.ReadFile(paths.ClientLinksText)
	if err != nil {
		t.Fatalf("read client links text: %v", err)
	}
	want := "# VLESS WS @whiteDNS\n" +
		"vless://uuid@vpn.example.com:443?type=ws&security=tls#VLESS%20WS%20%40whiteDNS\n\n" +
		"# Reality TCP Vision @whiteDNS\n" +
		"vless://uuid@reality.example.com:2083?type=tcp&security=reality&flow=xtls-rprx-vision#Reality%20TCP%20Vision%20%40whiteDNS\n\n"
	if string(data) != want {
		t.Fatalf("client links text = %q, want %q", string(data), want)
	}
	assertPerm(t, paths.ClientLinks, 0o600)
	assertPerm(t, paths.ClientLinksText, 0o600)
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s perm = %o, want %o", path, got, want)
	}
}
