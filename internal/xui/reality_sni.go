package xui

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/whitedns/wdns-wizard/internal/secrets"
)

const fallbackRealitySNI = "apple.com"

type RealitySNIValidator interface {
	Validate(ctx context.Context, hostname string) error
}

type tlsRealitySNIValidator struct {
	Timeout time.Duration
}

func (v tlsRealitySNIValidator) Validate(ctx context.Context, hostname string) error {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return fmt.Errorf("empty hostname")
	}
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := tls.Dialer{Config: &tls.Config{
		ServerName: hostname,
		MinVersion: tls.VersionTLS13,
	}}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(hostname, "443"))
	if err != nil {
		return err
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return fmt.Errorf("connection did not use TLS")
	}
	state := tlsConn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		return fmt.Errorf("TLS version %x is not TLS 1.3", state.Version)
	}
	return nil
}

type realitySNISelection struct {
	Key      string
	Old      string
	New      string
	Changed  bool
	Fallback bool
	Reason   string
}

type realitySNISelector struct {
	Validator  RealitySNIValidator
	Candidates []string
	Fallback   string
	Shuffle    bool
}

func defaultRealitySNISelector(validator RealitySNIValidator) realitySNISelector {
	if validator == nil {
		validator = tlsRealitySNIValidator{}
	}
	return realitySNISelector{
		Validator:  validator,
		Candidates: secrets.RealitySNICandidates(),
		Fallback:   fallbackRealitySNI,
		Shuffle:    true,
	}
}

func (s realitySNISelector) Select(ctx context.Context, key, current string) realitySNISelection {
	current = strings.TrimSpace(current)
	fallback := strings.TrimSpace(s.Fallback)
	if fallback == "" {
		fallback = fallbackRealitySNI
	}
	if s.Validator == nil {
		s.Validator = tlsRealitySNIValidator{}
	}
	if current != "" {
		candidates := normalizedRealityCandidates(s.Candidates, fallback)
		if !realitySNIAllowed(candidates, current) {
			return s.selectReplacement(ctx, key, current, fallback, "saved SNI is not in the current allowed set")
		}
		if err := s.Validator.Validate(ctx, current); err == nil {
			return realitySNISelection{Key: key, Old: current, New: current}
		} else {
			return s.selectReplacement(ctx, key, current, fallback, err.Error())
		}
	}
	return s.selectReplacement(ctx, key, current, fallback, "empty saved SNI")
}

func realitySNIAllowed(candidates []string, current string) bool {
	for _, candidate := range candidates {
		if candidate == current {
			return true
		}
	}
	return false
}

func (s realitySNISelector) selectReplacement(ctx context.Context, key, current, fallback, reason string) realitySNISelection {
	candidates := normalizedRealityCandidates(s.Candidates, fallback)
	if s.Shuffle {
		shuffleStrings(candidates)
	}
	for _, candidate := range candidates {
		if candidate == current {
			continue
		}
		if err := s.Validator.Validate(ctx, candidate); err == nil {
			return realitySNISelection{
				Key:     key,
				Old:     current,
				New:     candidate,
				Changed: candidate != current,
				Reason:  reason,
			}
		}
	}
	return realitySNISelection{
		Key:      key,
		Old:      current,
		New:      fallback,
		Changed:  fallback != current,
		Fallback: true,
		Reason:   reason,
	}
}

func normalizedRealityCandidates(candidates []string, fallback string) []string {
	seen := map[string]bool{}
	var normalized []string
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		normalized = append(normalized, candidate)
	}
	if !seen[fallback] {
		normalized = append(normalized, fallback)
	}
	return normalized
}

func shuffleStrings(values []string) {
	for i := len(values) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return
		}
		j := int(n.Int64())
		values[i], values[j] = values[j], values[i]
	}
}
