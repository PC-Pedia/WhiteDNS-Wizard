package xui

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whitedns/wdns-wizard/internal/output"
	"github.com/whitedns/wdns-wizard/internal/secrets"
	"github.com/whitedns/wdns-wizard/pkg/types"
	"gopkg.in/yaml.v3"
)

func TestProjectSummariesSortsByLastApplied(t *testing.T) {
	root := t.TempDir()
	writeProjectFiles(t, root, "old.example", "1.1.1.1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	writeProjectFiles(t, root, "new.example", "2.2.2.2", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))

	summaries, err := ProjectSummaries(root)
	if err != nil {
		t.Fatalf("ProjectSummaries returned error: %v", err)
	}
	if len(summaries) != 2 {
		t.Fatalf("summaries = %d, want 2", len(summaries))
	}
	if summaries[0].Domain != "new.example" || summaries[0].SSHHost != "2.2.2.2" {
		t.Fatalf("unexpected first summary: %+v", summaries[0])
	}
}

func TestRenderCurrentInfoIncludesImportantFields(t *testing.T) {
	root := t.TempDir()
	appliedAt := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	writeProjectFiles(t, root, "example.com", "1.2.3.4", appliedAt)

	info, err := LoadCurrentInfo(root, "example.com")
	if err != nil {
		t.Fatalf("LoadCurrentInfo returned error: %v", err)
	}
	body := RenderCurrentInfo(info)
	for _, want := range []string{
		"Project: example.com",
		"VPS IP: 1.2.3.4",
		"Zone: example.com (active)",
		"Client links:",
		"VLESS WS @whiteDNS",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("current info did not contain %q:\n%s", want, body)
		}
	}
}

func TestDashboardInfoUsesPublicPanelURL(t *testing.T) {
	t.Setenv(secrets.EnvKeyName, "")
	root := t.TempDir()
	appliedAt := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	writeProjectFiles(t, root, "example.com", "1.2.3.4", appliedAt)
	writeProjectSecrets(t, root, "example.com", map[string]string{
		"panel_username":  "WhiteDNS-user",
		"panel_password":  "panel-secret",
		"panel_base_path": "/tp-panel/",
	})

	info, err := NewProvisioner().DashboardInfo("example.com", root)
	if err != nil {
		t.Fatalf("DashboardInfo returned error: %v", err)
	}
	body := RenderDashboardInfo(info)
	for _, want := range []string{
		"Panel URL: http://panel.example.com:2053/tp-panel/",
		"Username: WhiteDNS-user",
		"Password: panel-secret",
		"Base path: /tp-panel/",
		"Private tunnel fallback: ssh -L 127.0.0.1:2053:127.0.0.1:2053 root@1.2.3.4",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard info did not contain %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "Panel URL after tunnel") {
		t.Fatalf("dashboard info should not use old tunnel-primary wording:\n%s", body)
	}
}

func TestRenderClientsShowsFirstTenPreparedClients(t *testing.T) {
	var clients []ClientSummary
	for i := 0; i < 10; i++ {
		clients = append(clients, ClientSummary{Inbound: "inbound", Email: "client" + string(rune('a'+i)), Enabled: true, Identifier: "id"})
	}
	body := RenderClients(clients)
	if strings.Count(body, "inbound") != 10 {
		t.Fatalf("rendered clients should include 10 rows:\n%s", body)
	}
}

func TestManagedCleanupHelpersOnlyMatchWhiteDNS(t *testing.T) {
	inbounds := []Inbound{
		{ID: 1, Tag: "wdns-vless-ws"},
		{ID: 2, Remark: "user-inbound"},
		{ID: 3, Settings: map[string]any{"clients": []any{map[string]any{"email": "wdns-direct-example-com"}}}},
	}
	ids := managedInboundIDs(inbounds)
	if len(ids) != 2 || ids[0] != 1 || ids[1] != 3 {
		t.Fatalf("managed ids = %+v, want [1 3]", ids)
	}

	config := map[string]any{
		"outbounds": []any{
			map[string]any{"tag": "wdns-direct", "protocol": "freedom"},
			map[string]any{"tag": "user-out", "protocol": "freedom"},
			map[string]any{"tag": "wdns-blocked", "protocol": "blackhole"},
			map[string]any{"tag": "wdns-tor", "protocol": "socks"},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"type": "field", "outboundTag": "wdns-tor", "inboundTag": []any{"wdns-tor-vless-ws"}},
		}},
	}
	config = RemoveManagedOutbounds(config)
	remaining := outbounds(config)
	if len(remaining) != 1 || remaining[0]["tag"] != "user-out" {
		t.Fatalf("remaining outbounds = %+v", remaining)
	}
	if missing := missingTorRoutingTags(config); len(missing) != len(torInboundTags()) {
		t.Fatalf("tor routing should be removed, missing = %+v", missing)
	}
}

func TestRenderDiagnosticsShowsStatuses(t *testing.T) {
	body := RenderDiagnostics(DiagnosticsResult{
		ProjectDir: "/tmp/project",
		Checks: []DiagnosticCheck{
			{Name: "docker", Status: "PASS", Detail: "running"},
			{Name: "panel", Status: "FAIL", Detail: "connection refused"},
		},
	})
	for _, want := range []string{"Project: /tmp/project", "PASS", "docker", "FAIL", "connection refused"} {
		if !strings.Contains(body, want) {
			t.Fatalf("diagnostics render missing %q:\n%s", want, body)
		}
	}
}

func TestHysteria2ConfigDiagnosticsRequireClientsAuthH3AndObfs(t *testing.T) {
	var checks []DiagnosticCheck
	add := func(name, status, detail string) {
		checks = append(checks, DiagnosticCheck{Name: name, Status: status, Detail: detail})
	}
	addHysteria2ConfigChecks(add, []Inbound{{
		Tag:      "wdns-hysteria2",
		Protocol: "hysteria",
		Port:     443,
		Settings: map[string]any{
			"version": 2,
			"clients": []map[string]any{{
				"auth":   "secret",
				"email":  "WhiteDNS-hy2-example-com",
				"enable": true,
			}},
		},
		StreamSettings: map[string]any{
			"network":  "hysteria",
			"security": "tls",
			"hysteriaSettings": map[string]any{
				"auth":           "secret",
				"version":        2,
				"udpIdleTimeout": 60,
			},
			"tlsSettings": map[string]any{
				"alpn": []string{"h3"},
			},
			"finalmask": map[string]any{
				"udp": []map[string]any{
					{
						"type":     "salamander",
						"settings": map[string]any{"password": "obfs-secret"},
					},
				},
				"quicParams": map[string]any{"congestion": "bbr"},
			},
		},
	}})

	body := RenderDiagnostics(DiagnosticsResult{ProjectDir: "/tmp/project", Checks: checks})
	for _, want := range []string{"PASS  hysteria2 clients", "PASS  hysteria2 auth", "PASS  hysteria2 alpn", "PASS  hysteria2 obfs"} {
		if !strings.Contains(body, want) {
			t.Fatalf("diagnostics missing %q:\n%s", want, body)
		}
	}
}

func TestShadowsocksConfigDiagnosticsRequireMethodPasswordsAndNetwork(t *testing.T) {
	var checks []DiagnosticCheck
	add := func(name, status, detail string) {
		checks = append(checks, DiagnosticCheck{Name: name, Status: status, Detail: detail})
	}
	addShadowsocksConfigChecks(add, []Inbound{{
		Tag:      "wdns-shadowsocks",
		Protocol: "shadowsocks",
		Port:     8388,
		Settings: map[string]any{
			"method":   shadowsocksMethod(),
			"password": "server-secret",
			"network":  "tcp,udp",
			"clients": []map[string]any{{
				"password": "client-secret",
				"email":    "WhiteDNS-ss-example-com",
				"enable":   true,
			}},
		},
		StreamSettings: map[string]any{
			"network":  "tcp",
			"security": "none",
		},
	}})

	body := RenderDiagnostics(DiagnosticsResult{ProjectDir: "/tmp/project", Checks: checks})
	for _, want := range []string{"PASS  shadowsocks method", "PASS  shadowsocks server password", "PASS  shadowsocks network", "PASS  shadowsocks client password"} {
		if !strings.Contains(body, want) {
			t.Fatalf("diagnostics missing %q:\n%s", want, body)
		}
	}
}

func TestTorXrayConfigDiagnosticsRequireOutboundAndRouting(t *testing.T) {
	var checks []DiagnosticCheck
	add := func(name, status, detail string) {
		checks = append(checks, DiagnosticCheck{Name: name, Status: status, Detail: detail})
	}
	config := EnsureOutbounds(map[string]any{
		"outbounds": []any{map[string]any{"tag": "user-out", "protocol": "freedom"}},
	})
	addTorXrayConfigChecks(add, config)

	body := RenderDiagnostics(DiagnosticsResult{ProjectDir: "/tmp/project", Checks: checks})
	for _, want := range []string{"PASS  tor outbound", "PASS  tor routing"} {
		if !strings.Contains(body, want) {
			t.Fatalf("diagnostics missing %q:\n%s", want, body)
		}
	}
}

func TestClientsFromSettingsIncludesHysteriaUsers(t *testing.T) {
	clients := clientsFromSettings(map[string]any{
		"users": []map[string]any{{
			"auth":  "secret",
			"email": "WhiteDNS-hy2-example-com",
			"level": 0,
		}},
	})
	if len(clients) != 1 || clients[0]["email"] != "WhiteDNS-hy2-example-com" {
		t.Fatalf("clients = %+v, want hysteria user", clients)
	}
	summary := summarizeClient("Hysteria2 @whiteDNS", clients[0])
	if !summary.Enabled || summary.Identifier != "auth:***" {
		t.Fatalf("summary = %+v, want enabled masked auth", summary)
	}
}

func TestBackupManagedCopiesLocalProjectAndRemoteArchive(t *testing.T) {
	root := t.TempDir()
	writeProjectFiles(t, root, "example.com", "1.2.3.4", time.Now().UTC())
	writeProjectSecrets(t, root, "example.com", map[string]string{"panel_username": "admin", "panel_password": "secret", "panel_base_path": "/panel/"})
	remoteArchive := base64.StdEncoding.EncodeToString([]byte("remote archive"))
	provisioner := Provisioner{RemoteFactory: func(ctx context.Context, cfg SSHConfig) (Remote, error) {
		return &fakeRemote{outputs: map[string]string{"tar -C": remoteArchive}}, nil
	}}
	result, err := provisioner.BackupManaged(context.Background(), Input{
		Domain: "example.com",
		Root:   root,
		SSH:    SSHConfig{Host: "1.2.3.4", User: "root", Password: "pw"},
	})
	if err != nil {
		t.Fatalf("BackupManaged returned error: %v", err)
	}
	if !fileExists(filepath.Join(result.LocalBackupDir, "config.yaml")) {
		t.Fatalf("local backup did not include config: %+v", result)
	}
	data, err := os.ReadFile(result.RemoteArchive)
	if err != nil {
		t.Fatalf("read remote archive: %v", err)
	}
	if string(data) != "remote archive" {
		t.Fatalf("remote archive = %q", data)
	}
}

func writeProjectFiles(t *testing.T, root, domain, ip string, appliedAt time.Time) {
	t.Helper()
	paths := output.Paths(root, domain)
	if err := os.MkdirAll(filepath.Dir(paths.Config), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	config := types.ProjectConfig{
		Project: domain,
		VPSIP:   ip,
	}
	writeYAMLTest(t, paths.Config, config)
	writeJSONTest(t, paths.CloudflareState, types.CloudflareState{
		Zone:      types.Zone{Name: domain, Status: "active"},
		AppliedAt: appliedAt,
		DNSResults: []types.DNSRecordResult{{
			Record: types.DNSRecord{Name: "vpn." + domain},
			Status: types.DNSRecordUnchanged,
		}},
	})
	writeJSONTest(t, paths.XUIState, types.XUIState{
		Domain:     domain,
		RemoteHost: ip,
		AppliedAt:  appliedAt,
	})
	writeYAMLTest(t, paths.ProtocolPlan, types.ProtocolPlan{Protocols: []types.Protocol{{
		Enabled:   true,
		Tag:       "wdns-vless-ws",
		Hostname:  "vpn." + domain,
		Port:      443,
		Network:   "tcp",
		Transport: "ws",
	}}})
}

func writeProjectSecrets(t *testing.T, root, domain string, values map[string]string) {
	t.Helper()
	paths := output.Paths(root, domain)
	key, err := secrets.LoadOrCreateKey(filepath.Join(root, ".secrets.key"))
	if err != nil {
		t.Fatalf("load secrets key: %v", err)
	}
	envelope, err := secrets.EncryptMap(values, key)
	if err != nil {
		t.Fatalf("encrypt secrets: %v", err)
	}
	writeYAMLTest(t, paths.Secrets, envelope)
}

func writeYAMLTest(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data, err := yaml.Marshal(value)
	if err != nil {
		t.Fatalf("marshal yaml: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
}

func writeJSONTest(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write json: %v", err)
	}
}
