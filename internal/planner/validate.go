package planner

import (
	"fmt"
	"net"
	"strings"
)

func NormalizeDomain(domain string) (string, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", fmt.Errorf("domain is required")
	}
	if strings.ContainsAny(domain, "/: ") {
		return "", fmt.Errorf("domain must be a bare DNS name")
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("domain must include a TLD")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("domain has an invalid label")
		}
	}
	return domain, nil
}

func ValidateIPv4(ip string) (string, error) {
	ip = strings.TrimSpace(ip)
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return "", fmt.Errorf("VPS IP must be a valid IPv4 address")
	}
	return ip, nil
}
