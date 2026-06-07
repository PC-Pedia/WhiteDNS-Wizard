package planner

import (
	"github.com/whitedns/wdns-wizard/internal/secrets"
	"github.com/whitedns/wdns-wizard/pkg/types"
)

func GenerateProtocolPlan(domain string, generated secrets.GeneratedSecrets) types.ProtocolPlan {
	clientSuffix := clientSuffix(domain)
	return types.ProtocolPlan{Protocols: []types.Protocol{
		{
			Name:              "vless_ws_tls",
			Enabled:           true,
			Hostname:          "vpn." + domain,
			Port:              443,
			Network:           "tcp",
			Transport:         "ws",
			Tag:               "wdns-vless-ws",
			ClientEmail:       "WhiteDNS-vless-" + clientSuffix,
			Path:              generated.VLESSWSPath,
			TLS:               true,
			CloudflareProxied: true,
			Certificate:       "origin_ca",
		},
		{
			Name:              "vless_ws_tls_8443",
			Enabled:           true,
			Hostname:          "trojan." + domain,
			Port:              8443,
			Network:           "tcp",
			Transport:         "ws",
			Tag:               "wdns-vless-ws-8443",
			ClientEmail:       "WhiteDNS-vless-8443-" + clientSuffix,
			Path:              generated.TrojanWSPath,
			TLS:               true,
			CloudflareProxied: true,
			Certificate:       "origin_ca",
		},
		{
			Name:              "hysteria2_direct",
			Enabled:           true,
			Hostname:          "hy2." + domain,
			Port:              443,
			Network:           "udp",
			Transport:         "hysteria2",
			Tag:               "wdns-hysteria2",
			ClientEmail:       "WhiteDNS-hy2-" + clientSuffix,
			UDP:               true,
			TLS:               true,
			CloudflareProxied: false,
			Certificate:       "public_acme",
		},
		{
			Name:              "direct_vless_tcp_tls",
			Enabled:           true,
			Hostname:          "direct." + domain,
			Port:              2087,
			Network:           "tcp",
			Transport:         "tcp",
			Tag:               "wdns-direct-vless",
			ClientEmail:       "WhiteDNS-direct-" + clientSuffix,
			TLS:               true,
			CloudflareProxied: false,
			Certificate:       "public_acme",
		},
		{
			Name:              "reality_tcp_vision_direct",
			Enabled:           true,
			Hostname:          "reality." + domain,
			Port:              2083,
			Network:           "tcp",
			Transport:         "tcp",
			Tag:               "wdns-reality-tcp-vision",
			ClientEmail:       "WhiteDNS-reality-" + clientSuffix,
			TLS:               true,
			CloudflareProxied: false,
			Certificate:       "reality",
		},
		{
			Name:              "shadowsocks_direct",
			Enabled:           true,
			Hostname:          "ss." + domain,
			Port:              8388,
			Network:           "tcp,udp",
			Transport:         "shadowsocks",
			Tag:               "wdns-shadowsocks",
			ClientEmail:       "WhiteDNS-ss-" + clientSuffix,
			CloudflareProxied: false,
			Certificate:       "none",
		},
		{
			Name:              "tor_vless_ws_tls",
			Enabled:           true,
			Hostname:          "tor-vless-ws." + domain,
			Port:              2097,
			Network:           "tcp",
			Transport:         "ws",
			Tag:               "wdns-tor-vless-ws",
			ClientEmail:       "WhiteDNS-tor-vless-" + clientSuffix,
			Path:              generated.VLESSWSPath,
			TLS:               true,
			CloudflareProxied: false,
			Certificate:       "public_acme",
		},
		{
			Name:              "tor_vless_ws_tls_8443",
			Enabled:           true,
			Hostname:          "tor-vless-ws-8443." + domain,
			Port:              2098,
			Network:           "tcp",
			Transport:         "ws",
			Tag:               "wdns-tor-vless-ws-8443",
			ClientEmail:       "WhiteDNS-tor-vless-8443-" + clientSuffix,
			Path:              generated.TrojanWSPath,
			TLS:               true,
			CloudflareProxied: false,
			Certificate:       "public_acme",
		},
		{
			Name:              "tor_hysteria2_direct",
			Enabled:           true,
			Hostname:          "tor-hy2." + domain,
			Port:              2099,
			Network:           "udp",
			Transport:         "hysteria2",
			Tag:               "wdns-tor-hysteria2",
			ClientEmail:       "WhiteDNS-tor-hy2-" + clientSuffix,
			UDP:               true,
			TLS:               true,
			CloudflareProxied: false,
			Certificate:       "public_acme",
		},
		{
			Name:              "tor_direct_vless_tcp_tls",
			Enabled:           true,
			Hostname:          "tor-direct." + domain,
			Port:              2100,
			Network:           "tcp",
			Transport:         "tcp",
			Tag:               "wdns-tor-direct-vless",
			ClientEmail:       "WhiteDNS-tor-direct-" + clientSuffix,
			TLS:               true,
			CloudflareProxied: false,
			Certificate:       "public_acme",
		},
		{
			Name:              "tor_reality_tcp_vision_direct",
			Enabled:           true,
			Hostname:          "tor-reality." + domain,
			Port:              2101,
			Network:           "tcp",
			Transport:         "tcp",
			Tag:               "wdns-tor-reality-tcp-vision",
			ClientEmail:       "WhiteDNS-tor-reality-" + clientSuffix,
			TLS:               true,
			CloudflareProxied: false,
			Certificate:       "reality",
		},
		{
			Name:              "tor_shadowsocks_direct",
			Enabled:           true,
			Hostname:          "tor-ss." + domain,
			Port:              8390,
			Network:           "tcp,udp",
			Transport:         "shadowsocks",
			Tag:               "wdns-tor-shadowsocks",
			ClientEmail:       "WhiteDNS-tor-ss-" + clientSuffix,
			CloudflareProxied: false,
			Certificate:       "none",
		},
	}}
}

func clientSuffix(domain string) string {
	out := make([]byte, 0, len(domain))
	for i := 0; i < len(domain); i++ {
		ch := domain[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
			out = append(out, ch)
		} else {
			out = append(out, '-')
		}
	}
	return string(out)
}
