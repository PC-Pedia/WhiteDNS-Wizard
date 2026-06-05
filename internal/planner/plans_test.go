package planner

import (
	"testing"

	"github.com/whitedns/wdns-wizard/internal/secrets"
)

func TestGenerateDNSPlan(t *testing.T) {
	plan := GenerateDNSPlan("example.com", "1.2.3.4")
	if len(plan.Records) != 13 {
		t.Fatalf("records = %d, want 13", len(plan.Records))
	}
	if plan.Records[0].Name != "vpn.example.com" || !plan.Records[0].Proxied {
		t.Fatalf("unexpected first record: %+v", plan.Records[0])
	}
	if plan.Records[1].Name != "trojan.example.com" || plan.Records[1].Purpose != "vless_ws_tls_8443" {
		t.Fatalf("unexpected 8443 vless record: %+v", plan.Records[1])
	}
	if plan.Records[4].Name != "hy2.example.com" || plan.Records[4].Proxied {
		t.Fatalf("unexpected hy2 record: %+v", plan.Records[4])
	}
	if plan.Records[3].Name != "direct.example.com" || plan.Records[3].Proxied {
		t.Fatalf("unexpected direct record: %+v", plan.Records[3])
	}
	if plan.Records[5].Name != "reality.example.com" || plan.Records[5].Proxied || plan.Records[5].Purpose != "reality_xhttp_direct" {
		t.Fatalf("unexpected reality record: %+v", plan.Records[5])
	}
	if plan.Records[6].Name != "ss.example.com" || plan.Records[6].Proxied || plan.Records[6].Purpose != "shadowsocks_direct" {
		t.Fatalf("unexpected shadowsocks record: %+v", plan.Records[6])
	}
	records := map[string]string{}
	for _, record := range plan.Records {
		if record.Proxied {
			continue
		}
		records[record.Name] = record.Purpose
	}
	for host, purpose := range map[string]string{
		"tor-vless-ws.example.com":      "tor_vless_ws_tls",
		"tor-vless-ws-8443.example.com": "tor_vless_ws_tls_8443",
		"tor-hy2.example.com":           "tor_hysteria2_direct",
		"tor-direct.example.com":        "tor_direct_vless_tcp_tls",
		"tor-reality.example.com":       "tor_reality_xhttp_direct",
		"tor-ss.example.com":            "tor_shadowsocks_direct",
	} {
		if records[host] != purpose {
			t.Fatalf("record %s purpose = %q, want %q", host, records[host], purpose)
		}
	}
}

func TestGenerateProtocolPlan(t *testing.T) {
	plan := GenerateProtocolPlan("example.com", secrets.GeneratedSecrets{
		VLESSWSPath:       "/tp-vless",
		TrojanWSPath:      "/tp-trojan",
		DirectVLESSUUID:   "direct-uuid",
		RealityVLESSUUID:  "reality-uuid",
		RealityPrivateKey: "reality-private",
		RealityPublicKey:  "reality-public",
		RealityShortID:    "reality-short",
	})
	if len(plan.Protocols) != 12 {
		t.Fatalf("protocols = %d, want 12", len(plan.Protocols))
	}
	if plan.Protocols[0].Hostname != "vpn.example.com" || plan.Protocols[0].Port != 443 || plan.Protocols[0].Path != "/tp-vless" {
		t.Fatalf("unexpected vless protocol: %+v", plan.Protocols[0])
	}
	if plan.Protocols[1].Name != "vless_ws_tls_8443" || plan.Protocols[1].Tag != "wdns-vless-ws-8443" || plan.Protocols[1].Port != 8443 {
		t.Fatalf("unexpected 8443 vless protocol: %+v", plan.Protocols[1])
	}
	if !plan.Protocols[2].Enabled || !plan.Protocols[2].UDP || plan.Protocols[2].Hostname != "hy2.example.com" {
		t.Fatalf("unexpected hysteria2 protocol: %+v", plan.Protocols[2])
	}
	if !plan.Protocols[3].Enabled || plan.Protocols[3].Hostname != "direct.example.com" || plan.Protocols[3].Port != 2087 {
		t.Fatalf("unexpected direct protocol: %+v", plan.Protocols[3])
	}
	if !plan.Protocols[4].Enabled || plan.Protocols[4].Hostname != "reality.example.com" || plan.Protocols[4].Port != 2083 || plan.Protocols[4].Transport != "xhttp" {
		t.Fatalf("unexpected reality protocol: %+v", plan.Protocols[4])
	}
	if !plan.Protocols[5].Enabled || plan.Protocols[5].Hostname != "ss.example.com" || plan.Protocols[5].Port != 8388 || plan.Protocols[5].Network != "tcp,udp" || plan.Protocols[5].Transport != "shadowsocks" {
		t.Fatalf("unexpected shadowsocks protocol: %+v", plan.Protocols[5])
	}
	protocols := map[string]struct {
		hostname string
		port     int
		network  string
	}{}
	for _, proto := range plan.Protocols {
		protocols[proto.Tag] = struct {
			hostname string
			port     int
			network  string
		}{proto.Hostname, proto.Port, proto.Network}
	}
	for tag, want := range map[string]struct {
		hostname string
		port     int
		network  string
	}{
		"wdns-tor-vless-ws":      {"tor-vless-ws.example.com", 2097, "tcp"},
		"wdns-tor-vless-ws-8443": {"tor-vless-ws-8443.example.com", 2098, "tcp"},
		"wdns-tor-hysteria2":     {"tor-hy2.example.com", 2099, "udp"},
		"wdns-tor-direct-vless":  {"tor-direct.example.com", 2100, "tcp"},
		"wdns-tor-reality-xhttp": {"tor-reality.example.com", 2101, "tcp"},
		"wdns-tor-shadowsocks":   {"tor-ss.example.com", 8390, "tcp,udp"},
	} {
		got, ok := protocols[tag]
		if !ok || got != want {
			t.Fatalf("protocol %s = %+v, want %+v", tag, got, want)
		}
	}
}
