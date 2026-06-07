package xui

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/whitedns/wdns-wizard/pkg/types"
)

func DetectConflicts(inbounds []Inbound, xrayConfig map[string]any, planned []Inbound) []types.XUIConflict {
	var conflicts []types.XUIConflict
	for _, existing := range inbounds {
		for _, want := range planned {
			if existing.Tag == want.Tag || existing.Remark == want.Remark {
				conflicts = append(conflicts, types.XUIConflict{
					Kind:   "inbound",
					Name:   DisplayNameForTag(want.Tag),
					Detail: fmt.Sprintf("existing inbound %q uses WhiteDNS tag/remark", existing.Tag),
					Action: "replace",
				})
				break
			}
			if existing.Port == want.Port {
				conflicts = append(conflicts, types.XUIConflict{
					Kind:   "port",
					Name:   strconv.Itoa(want.Port),
					Detail: fmt.Sprintf("existing inbound %q already uses port %d", existing.Tag, want.Port),
					Action: "replace",
				})
				break
			}
			if inboundHasAnyClientEmail(existing, clientEmailAliases(firstClientEmail(want))...) {
				conflicts = append(conflicts, types.XUIConflict{
					Kind:   "client",
					Name:   firstClientEmail(want),
					Detail: fmt.Sprintf("existing inbound %q already has this client email", existing.Tag),
					Action: "replace",
				})
				break
			}
		}
	}
	for _, tag := range managedOutboundTags() {
		if outboundProtocol(xrayConfig, tag) != "" {
			conflicts = append(conflicts, types.XUIConflict{
				Kind:   "outbound",
				Name:   DisplayNameForTag(tag),
				Detail: "xray config already contains a WhiteDNS outbound tag",
				Action: "replace",
			})
		}
	}
	return dedupeConflicts(conflicts)
}

func firstClientEmail(inbound Inbound) string {
	for _, key := range []string{"clients", "users"} {
		clients, ok := inbound.Settings[key].([]map[string]any)
		if ok && len(clients) > 0 {
			if email, ok := clients[0]["email"].(string); ok {
				return email
			}
		}
		rawClients, ok := inbound.Settings[key].([]any)
		if ok && len(rawClients) > 0 {
			if m, ok := rawClients[0].(map[string]any); ok {
				if email, ok := m["email"].(string); ok {
					return email
				}
			}
		}
	}
	return ""
}

func inboundHasClientEmail(inbound Inbound, email string) bool {
	if email == "" {
		return false
	}
	data, _ := json.Marshal(inbound.Settings)
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return false
	}
	for _, key := range []string{"clients", "users"} {
		clients, _ := parsed[key].([]any)
		for _, item := range clients {
			client, _ := item.(map[string]any)
			if strings.EqualFold(fmt.Sprint(client["email"]), email) {
				return true
			}
		}
	}
	return false
}

func inboundHasAnyClientEmail(inbound Inbound, emails ...string) bool {
	for _, email := range emails {
		if inboundHasClientEmail(inbound, email) {
			return true
		}
	}
	return false
}

func clientEmailAliases(email string) []string {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil
	}
	aliases := []string{email}
	if strings.HasPrefix(email, "WhiteDNS-") {
		aliases = append(aliases, "wdns-"+strings.TrimPrefix(email, "WhiteDNS-"))
	}
	if strings.HasPrefix(strings.ToLower(email), "whitedns-") && !strings.HasPrefix(email, "WhiteDNS-") {
		aliases = append(aliases, "wdns-"+email[len("whitedns-"):])
	}
	if strings.HasPrefix(email, "wdns-") {
		aliases = append(aliases, "WhiteDNS-"+strings.TrimPrefix(email, "wdns-"))
	}
	return aliases
}

func outboundProtocol(config map[string]any, tag string) string {
	for _, outbound := range outbounds(config) {
		if fmt.Sprint(outbound["tag"]) == tag {
			return fmt.Sprint(outbound["protocol"])
		}
	}
	return ""
}

func outbounds(config map[string]any) []map[string]any {
	raw, ok := config["outbounds"].([]any)
	if !ok {
		return nil
	}
	var result []map[string]any
	for _, item := range raw {
		if outbound, ok := item.(map[string]any); ok {
			result = append(result, outbound)
		}
	}
	return result
}

func EnsureOutbounds(config map[string]any) map[string]any {
	var kept []any
	for _, outbound := range outbounds(config) {
		tag := fmt.Sprint(outbound["tag"])
		if isManagedOutboundTag(tag) {
			continue
		}
		kept = append(kept, outbound)
	}
	kept = append(kept, outboundDirect(), outboundBlocked(), outboundTor())
	config["outbounds"] = kept
	config = EnsureTorRouting(config)
	return config
}

func RemoveManagedOutbounds(config map[string]any) map[string]any {
	var kept []any
	for _, outbound := range outbounds(config) {
		tag := fmt.Sprint(outbound["tag"])
		if isManagedOutboundTag(tag) {
			continue
		}
		kept = append(kept, outbound)
	}
	config["outbounds"] = kept
	config = RemoveManagedTorRouting(config)
	return config
}

func EnsureTorRouting(config map[string]any) map[string]any {
	routing := routingConfig(config)
	var kept []any
	for _, rule := range routingRules(routing) {
		if isManagedTorRoutingRule(rule) {
			continue
		}
		kept = append(kept, rule)
	}
	kept = append(kept, torRoutingRule())
	routing["rules"] = kept
	config["routing"] = routing
	return config
}

func RemoveManagedTorRouting(config map[string]any) map[string]any {
	routing := routingConfig(config)
	var kept []any
	for _, rule := range routingRules(routing) {
		if isManagedTorRoutingRule(rule) {
			continue
		}
		kept = append(kept, rule)
	}
	routing["rules"] = kept
	config["routing"] = routing
	return config
}

func routingConfig(config map[string]any) map[string]any {
	if routing, ok := config["routing"].(map[string]any); ok {
		return routing
	}
	routing := map[string]any{"domainStrategy": "IPIfNonMatch"}
	config["routing"] = routing
	return routing
}

func routingRules(routing map[string]any) []map[string]any {
	switch raw := routing["rules"].(type) {
	case []map[string]any:
		return raw
	case []any:
		var result []map[string]any
		for _, item := range raw {
			if rule, ok := item.(map[string]any); ok {
				result = append(result, rule)
			}
		}
		return result
	default:
		return nil
	}
}

func torRoutingRule() map[string]any {
	return map[string]any{
		"type":        "field",
		"inboundTag":  torInboundTags(),
		"outboundTag": "wdns-tor",
	}
}

func isManagedTorRoutingRule(rule map[string]any) bool {
	return fmt.Sprint(rule["outboundTag"]) == "wdns-tor"
}

func managedOutboundTags() []string {
	return []string{"wdns-direct", "wdns-blocked", "wdns-tor"}
}

func isManagedOutboundTag(tag string) bool {
	for _, managed := range managedOutboundTags() {
		if tag == managed {
			return true
		}
	}
	return false
}

func torInboundTags() []string {
	return []string{
		"wdns-tor-vless-ws",
		"wdns-tor-vless-ws-8443",
		"wdns-tor-hysteria2",
		"wdns-tor-direct-vless",
		"wdns-tor-reality-tcp-vision",
		"wdns-tor-shadowsocks",
	}
}

func managedInboundIDs(inbounds []Inbound) []int {
	var ids []int
	seen := map[int]bool{}
	for _, inbound := range inbounds {
		if inbound.ID == 0 || seen[inbound.ID] {
			continue
		}
		if isWhiteDNSIdentifier(inbound.Tag) ||
			isWhiteDNSIdentifier(inbound.Remark) ||
			isWhiteDNSIdentifier(firstClientEmail(inbound)) {
			ids = append(ids, inbound.ID)
			seen[inbound.ID] = true
		}
	}
	return ids
}

func matchingInboundIDs(inbounds []Inbound, planned []Inbound) []int {
	seen := map[int]bool{}
	var ids []int
	for _, existing := range inbounds {
		for _, want := range planned {
			if existing.Tag == want.Tag || existing.Remark == want.Remark || existing.Port == want.Port || inboundHasAnyClientEmail(existing, clientEmailAliases(firstClientEmail(want))...) {
				if existing.ID != 0 && !seen[existing.ID] {
					ids = append(ids, existing.ID)
					seen[existing.ID] = true
				}
			}
		}
	}
	return ids
}

func isWhiteDNSIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	return strings.HasPrefix(lower, "wdns-") ||
		strings.HasPrefix(lower, "whitedns-") ||
		strings.HasPrefix(lower, "whitedns ")
}

func dedupeConflicts(conflicts []types.XUIConflict) []types.XUIConflict {
	seen := map[string]bool{}
	var out []types.XUIConflict
	for _, conflict := range conflicts {
		key := conflict.Kind + "\x00" + conflict.Name + "\x00" + conflict.Detail
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, conflict)
	}
	return out
}
