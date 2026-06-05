package planner

import "testing"

func TestNormalizeDomain(t *testing.T) {
	got, err := NormalizeDomain(" https://Example.COM. ")
	if err != nil {
		t.Fatalf("NormalizeDomain returned error: %v", err)
	}
	if got != "example.com" {
		t.Fatalf("domain = %q, want example.com", got)
	}
}

func TestNormalizeDomainRejectsPath(t *testing.T) {
	if _, err := NormalizeDomain("example.com/path"); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateIPv4(t *testing.T) {
	got, err := ValidateIPv4("1.2.3.4")
	if err != nil {
		t.Fatalf("ValidateIPv4 returned error: %v", err)
	}
	if got != "1.2.3.4" {
		t.Fatalf("ip = %q, want 1.2.3.4", got)
	}
}

func TestValidateIPv4RejectsIPv6(t *testing.T) {
	if _, err := ValidateIPv4("2001:db8::1"); err == nil {
		t.Fatal("expected error")
	}
}
