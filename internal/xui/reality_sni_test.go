package xui

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/whitedns/wdns-wizard/pkg/types"
)

type fakeRealitySNIValidator map[string]bool

func (f fakeRealitySNIValidator) Validate(ctx context.Context, hostname string) error {
	if f[hostname] {
		return nil
	}
	return fmt.Errorf("%s failed TLS validation", hostname)
}

func TestRealitySNISelectorKeepsValidSavedSNI(t *testing.T) {
	selector := realitySNISelector{
		Validator:  fakeRealitySNIValidator{"docker.com": true},
		Candidates: []string{"apple.com", "docker.com"},
		Fallback:   fallbackRealitySNI,
	}
	selection := selector.Select(context.Background(), "reality_sni", "docker.com")
	if selection.Changed || selection.New != "docker.com" {
		t.Fatalf("selection = %+v, want unchanged docker.com", selection)
	}
}

func TestRealitySNISelectorRotatesSavedSNIOutsideAllowedSet(t *testing.T) {
	selector := realitySNISelector{
		Validator:  fakeRealitySNIValidator{"apple.com": true, "www.microsoft.com": true},
		Candidates: []string{"apple.com", "docker.com"},
		Fallback:   fallbackRealitySNI,
	}
	selection := selector.Select(context.Background(), "reality_sni", "www.microsoft.com")
	if !selection.Changed || selection.New != "apple.com" || selection.Fallback {
		t.Fatalf("selection = %+v, want rotation to apple.com", selection)
	}
}

func TestRealitySNISelectorRotatesInvalidSavedSNI(t *testing.T) {
	selector := realitySNISelector{
		Validator:  fakeRealitySNIValidator{"good.example": true},
		Candidates: []string{"bad.example", "good.example"},
		Fallback:   fallbackRealitySNI,
	}
	selection := selector.Select(context.Background(), "reality_sni", "bad.example")
	if !selection.Changed || selection.New != "good.example" || selection.Fallback {
		t.Fatalf("selection = %+v, want validated replacement good.example", selection)
	}
}

func TestRealitySNISelectorFallsBackWhenAllCandidatesFail(t *testing.T) {
	selector := realitySNISelector{
		Validator:  fakeRealitySNIValidator{},
		Candidates: []string{"bad.example", "worse.example"},
		Fallback:   fallbackRealitySNI,
	}
	selection := selector.Select(context.Background(), "reality_sni", "bad.example")
	if !selection.Changed || !selection.Fallback || selection.New != fallbackRealitySNI {
		t.Fatalf("selection = %+v, want fallback %s", selection, fallbackRealitySNI)
	}
}

func TestEnsureValidatedRealitySNIsKeepsRealityKeysStable(t *testing.T) {
	project := projectData{Secrets: map[string]string{
		"reality_sni":             "bad.example",
		"reality_private_key":     "private-key",
		"reality_public_key":      "public-key",
		"reality_short_id":        "short-id",
		"tor_reality_sni":         "tor-bad.example",
		"tor_reality_private_key": "tor-private-key",
	}}
	progress := newProgressRecorder(nil)
	changed := project.ensureValidatedRealitySNIs(context.Background(), fakeRealitySNIValidator{
		"apple.com": true,
	}, progress)
	if !changed {
		t.Fatal("expected invalid SNIs to be repaired")
	}
	if project.Secrets["reality_sni"] != "apple.com" || project.Secrets["tor_reality_sni"] != "apple.com" {
		t.Fatalf("unexpected SNIs after repair: %+v", project.Secrets)
	}
	if project.Secrets["reality_private_key"] != "private-key" || project.Secrets["reality_public_key"] != "public-key" || project.Secrets["reality_short_id"] != "short-id" || project.Secrets["tor_reality_private_key"] != "tor-private-key" {
		t.Fatalf("Reality identity secrets changed: %+v", project.Secrets)
	}
	if !strings.Contains(progress.Body(), "Reality SNI validation") || !strings.Contains(progress.Body(), "rotated") {
		t.Fatalf("progress log missing validation detail:\n%s", progress.Body())
	}
}

func TestRealityConfigDiagnosticsCompareServerAndClientSNI(t *testing.T) {
	var checks []DiagnosticCheck
	add := func(name, status, detail string) {
		checks = append(checks, DiagnosticCheck{Name: name, Status: status, Detail: detail})
	}
	addRealityConfigChecks(add, []Inbound{{
		Tag: "wdns-reality-xhttp",
		StreamSettings: map[string]any{
			"realitySettings": map[string]any{
				"target":      "apple.com:443",
				"serverNames": []string{"apple.com"},
			},
		},
	}, {
		Tag: "wdns-tor-reality-xhttp",
		StreamSettings: map[string]any{
			"realitySettings": map[string]any{
				"target":      "bad.example:443",
				"serverNames": []string{"bad.example"},
			},
		},
	}}, types.ClientLinks{Clients: []types.ClientLink{{
		Name: "Reality XHTTP @whiteDNS",
		Link: "vless://uuid@reality.example.com:2083?type=xhttp&security=reality&sni=apple.com",
	}, {
		Name: "Reality XHTTP Tor @whiteDNS",
		Link: "vless://uuid@tor-reality.example.com:2101?type=xhttp&security=reality&sni=apple.com",
	}}}, map[string]string{
		"reality_sni":     "apple.com",
		"tor_reality_sni": "apple.com",
	})
	body := RenderDiagnostics(DiagnosticsResult{ProjectDir: "/tmp/project", Checks: checks})
	for _, want := range []string{"PASS  reality config", "PASS  reality config link", "WARN  tor reality config"} {
		if !strings.Contains(body, want) {
			t.Fatalf("diagnostics missing %q:\n%s", want, body)
		}
	}
}
