package nodeconfig

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/perfect-panel/server/internal/config"
	"github.com/perfect-panel/server/internal/model/node"
	"github.com/perfect-panel/server/internal/types"
	"github.com/pkg/errors"
)

const (
	RoutingModeInherit  = "inherit"
	RoutingModeAppend   = "append"
	RoutingModeOverride = "override"
)

var reservedOutboundTags = map[string]struct{}{
	"Default": {},
	"direct":  {},
	"block":   {},
	"dns_out": {},
}

func GlobalValues(c config.NodeConfig) types.ServerNodeConfigValues {
	dns := make([]types.NodeDNS, 0, len(c.DNS))
	for _, d := range c.DNS {
		dns = append(dns, types.NodeDNS{
			Proto:   d.Proto,
			Address: d.Address,
			Domains: normalizeStrings(d.Domains),
		})
	}

	outbound := make([]types.NodeOutbound, 0, len(c.Outbound))
	for _, o := range c.Outbound {
		outbound = append(outbound, types.NodeOutbound{
			Name:                 o.Name,
			Protocol:             o.Protocol,
			Address:              o.Address,
			Port:                 o.Port,
			User:                 o.User,
			Password:             o.Password,
			UUID:                 o.UUID,
			Cipher:               o.Cipher,
			Security:             o.Security,
			SNI:                  o.SNI,
			AllowInsecure:        o.AllowInsecure,
			Fingerprint:          o.Fingerprint,
			Transport:            o.Transport,
			Host:                 o.Host,
			Path:                 o.Path,
			ServiceName:          o.ServiceName,
			Flow:                 o.Flow,
			UoT:                  o.UoT,
			UoTVersion:           o.UoTVersion,
			CongestionController: o.CongestionController,
			UDPStream:            o.UDPStream,
			ReduceRtt:            o.ReduceRtt,
			Heartbeat:            o.Heartbeat,
			RealityPublicKey:     o.RealityPublicKey,
			RealityShortId:       o.RealityShortId,
			SpiderX:              o.SpiderX,
			Settings:             o.Settings,
			StreamSettings:       o.StreamSettings,
			Rules:                normalizeStrings(o.Rules),
		})
	}

	return types.ServerNodeConfigValues{
		IPStrategy:   c.IPStrategy,
		DNS:          ensureDNS(dns),
		Block:        normalizeStrings(c.Block),
		Outbound:     ensureOutbound(outbound),
		RoutingRules: configRoutingRules(c.RoutingRules),
		RelayRules:   configRelayRules(c.RelayRules),
	}
}

func ApplyOverride(values *types.ServerNodeConfigValues, override *node.ServerConfigOverride) error {
	if values == nil || override == nil {
		return nil
	}

	if override.IPStrategy != nil {
		values.IPStrategy = *override.IPStrategy
	}
	if override.DNS != nil {
		var dns []types.NodeDNS
		if err := unmarshalJSONField(*override.DNS, &dns, "dns"); err != nil {
			return err
		}
		values.DNS = ensureDNS(dns)
	}
	if override.Block != nil {
		var block []string
		if err := unmarshalJSONField(*override.Block, &block, "block"); err != nil {
			return err
		}
		values.Block = normalizeStrings(block)
	}
	if override.Outbound != nil {
		var outbound []types.NodeOutbound
		if err := unmarshalJSONField(*override.Outbound, &outbound, "outbound"); err != nil {
			return err
		}
		values.Outbound = ensureOutbound(outbound)
	}
	if override.RoutingRules != nil {
		var rules []types.NodeRoutingRule
		if err := unmarshalJSONField(*override.RoutingRules, &rules, "routing_rules"); err != nil {
			return err
		}
		req := types.ServerNodeConfigOverride{
			InheritRoutingRules: false,
			RoutingMode:         stringValue(override.RoutingMode, RoutingModeOverride),
			RoutingRules:        rules,
		}
		if err := ApplyRoutingOverride(values, req); err != nil {
			return err
		}
	}
	if override.RelayRules != nil {
		var rules []types.NodeRelayRule
		if err := unmarshalJSONField(*override.RelayRules, &rules, "relay_rules"); err != nil {
			return err
		}
		values.RelayRules = NormalizeRelayRules(rules)
	}
	return nil
}

func OverrideResponse(override *node.ServerConfigOverride) (types.ServerNodeConfigOverride, error) {
	resp := types.ServerNodeConfigOverride{
		InheritIPStrategy:   true,
		InheritDNS:          true,
		InheritBlock:        true,
		InheritOutbound:     true,
		InheritRoutingRules: true,
		RoutingMode:         RoutingModeInherit,
		DNS:                 []types.NodeDNS{},
		Block:               []string{},
		Outbound:            []types.NodeOutbound{},
		RoutingRules:        []types.NodeRoutingRule{},
		InheritRelayRules:   true,
		RelayRules:          []types.NodeRelayRule{},
	}
	if override == nil || override.Id == 0 {
		return resp, nil
	}

	if override.IPStrategy != nil {
		resp.InheritIPStrategy = false
		resp.IPStrategy = *override.IPStrategy
	}
	if override.DNS != nil {
		resp.InheritDNS = false
		var dns []types.NodeDNS
		if err := unmarshalJSONField(*override.DNS, &dns, "dns"); err != nil {
			return resp, err
		}
		resp.DNS = ensureDNS(dns)
	}
	if override.Block != nil {
		resp.InheritBlock = false
		var block []string
		if err := unmarshalJSONField(*override.Block, &block, "block"); err != nil {
			return resp, err
		}
		resp.Block = normalizeStrings(block)
	}
	if override.Outbound != nil {
		resp.InheritOutbound = false
		var outbound []types.NodeOutbound
		if err := unmarshalJSONField(*override.Outbound, &outbound, "outbound"); err != nil {
			return resp, err
		}
		resp.Outbound = ensureOutbound(outbound)
	}
	if override.RoutingRules != nil {
		resp.InheritRoutingRules = false
		resp.RoutingMode = normalizeRoutingMode(stringValue(override.RoutingMode, RoutingModeOverride))
		var rules []types.NodeRoutingRule
		if err := unmarshalJSONField(*override.RoutingRules, &rules, "routing_rules"); err != nil {
			return resp, err
		}
		resp.RoutingRules = NormalizeRoutingRules(rules)
	}
	if override.RelayRules != nil {
		resp.InheritRelayRules = false
		var rules []types.NodeRelayRule
		if err := unmarshalJSONField(*override.RelayRules, &rules, "relay_rules"); err != nil {
			return resp, err
		}
		resp.RelayRules = NormalizeRelayRules(rules)
	}

	return resp, nil
}

func OverrideModel(serverID int64, req types.ServerNodeConfigOverride) (*node.ServerConfigOverride, bool, error) {
	data := &node.ServerConfigOverride{
		ServerId: serverID,
	}

	if !req.InheritIPStrategy {
		data.IPStrategy = stringPtr(req.IPStrategy)
	}
	if !req.InheritDNS {
		value, err := marshalJSONField(ensureDNS(req.DNS), "dns")
		if err != nil {
			return nil, false, err
		}
		data.DNS = &value
	}
	if !req.InheritBlock {
		value, err := marshalJSONField(normalizeStrings(req.Block), "block")
		if err != nil {
			return nil, false, err
		}
		data.Block = &value
	}
	if !req.InheritOutbound {
		value, err := marshalJSONField(ensureOutbound(req.Outbound), "outbound")
		if err != nil {
			return nil, false, err
		}
		data.Outbound = &value
	}
	if !req.InheritRoutingRules && (strings.TrimSpace(req.RoutingMode) != "" || len(req.RoutingRules) > 0) {
		mode := normalizeRoutingMode(req.RoutingMode)
		value, err := marshalJSONField(NormalizeRoutingRules(req.RoutingRules), "routing_rules")
		if err != nil {
			return nil, false, err
		}
		data.RoutingMode = &mode
		data.RoutingRules = &value
	}
	if !req.InheritRelayRules && len(req.RelayRules) > 0 {
		value, err := marshalJSONField(NormalizeRelayRules(req.RelayRules), "relay_rules")
		if err != nil {
			return nil, false, err
		}
		data.RelayRules = &value
	}

	allInherited := data.IPStrategy == nil && data.DNS == nil && data.Block == nil && data.Outbound == nil && data.RoutingRules == nil && data.RelayRules == nil
	return data, allInherited, nil
}

func CloneValues(values types.ServerNodeConfigValues) types.ServerNodeConfigValues {
	dns := make([]types.NodeDNS, 0, len(values.DNS))
	for _, d := range values.DNS {
		dns = append(dns, types.NodeDNS{
			Proto:   d.Proto,
			Address: d.Address,
			Domains: normalizeStrings(d.Domains),
		})
	}

	outbound := make([]types.NodeOutbound, 0, len(values.Outbound))
	for _, o := range values.Outbound {
		outbound = append(outbound, types.NodeOutbound{
			Name:                 o.Name,
			Protocol:             o.Protocol,
			Address:              o.Address,
			Port:                 o.Port,
			User:                 o.User,
			Password:             o.Password,
			UUID:                 o.UUID,
			Cipher:               o.Cipher,
			Security:             o.Security,
			SNI:                  o.SNI,
			AllowInsecure:        o.AllowInsecure,
			Fingerprint:          o.Fingerprint,
			Transport:            o.Transport,
			Host:                 o.Host,
			Path:                 o.Path,
			ServiceName:          o.ServiceName,
			Flow:                 o.Flow,
			UoT:                  o.UoT,
			UoTVersion:           o.UoTVersion,
			CongestionController: o.CongestionController,
			UDPStream:            o.UDPStream,
			ReduceRtt:            o.ReduceRtt,
			Heartbeat:            o.Heartbeat,
			RealityPublicKey:     o.RealityPublicKey,
			RealityShortId:       o.RealityShortId,
			SpiderX:              o.SpiderX,
			Settings:             o.Settings,
			StreamSettings:       o.StreamSettings,
			Rules:                normalizeStrings(o.Rules),
		})
	}

	return types.ServerNodeConfigValues{
		IPStrategy:   values.IPStrategy,
		DNS:          ensureDNS(dns),
		Block:        normalizeStrings(values.Block),
		Outbound:     ensureOutbound(outbound),
		RoutingRules: NormalizeRoutingRules(values.RoutingRules),
		RelayRules:   NormalizeRelayRules(values.RelayRules),
	}
}

func NormalizeRoutingRules(values []types.NodeRoutingRule) []types.NodeRoutingRule {
	if values == nil {
		return []types.NodeRoutingRule{}
	}
	result := make([]types.NodeRoutingRule, 0, len(values))
	for _, item := range values {
		rule := types.NodeRoutingRule{
			ID:          strings.TrimSpace(item.ID),
			Enabled:     item.Enabled,
			Sort:        item.Sort,
			Remark:      strings.TrimSpace(item.Remark),
			SourceIP:    normalizeStrings(item.SourceIP),
			SourcePort:  strings.TrimSpace(item.SourcePort),
			VlessRoute:  strings.TrimSpace(item.VlessRoute),
			InboundTags: normalizeStrings(item.InboundTags),
			OutboundTag: strings.TrimSpace(item.OutboundTag),
			BalancerTag: strings.TrimSpace(item.BalancerTag),
			Domain:      normalizeStrings(item.Domain),
			IP:          normalizeStrings(item.IP),
			User:        normalizeStrings(item.User),
			Port:        strings.TrimSpace(item.Port),
			Protocol:    strings.TrimSpace(item.Protocol),
			Attrs:       strings.TrimSpace(item.Attrs),
			Network:     strings.TrimSpace(item.Network),
		}
		if isEmptyRoutingRule(rule) {
			continue
		}
		result = append(result, rule)
	}
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].Sort < result[j].Sort
	})
	return result
}

func ValidateRoutingRules(rules []types.NodeRoutingRule, outbounds []types.NodeOutbound) error {
	available := map[string]struct{}{}
	for tag := range reservedOutboundTags {
		available[tag] = struct{}{}
	}
	for _, outbound := range ensureOutbound(outbounds) {
		if _, exists := available[outbound.Name]; exists {
			return fmt.Errorf("duplicate or reserved outbound tag %q", outbound.Name)
		}
		available[outbound.Name] = struct{}{}
	}

	for _, rule := range NormalizeRoutingRules(rules) {
		if !rule.Enabled {
			continue
		}
		hasOutbound := rule.OutboundTag != ""
		hasBalancer := rule.BalancerTag != ""
		if !hasOutbound && !hasBalancer {
			return fmt.Errorf("routing rule %q outbound_tag or balancer_tag is required", rule.ID)
		}
		if hasOutbound && hasBalancer {
			return fmt.Errorf("routing rule %q cannot use both outbound_tag and balancer_tag", rule.ID)
		}
		if hasOutbound {
			if _, exists := available[rule.OutboundTag]; !exists {
				return fmt.Errorf("routing rule %q references unknown outbound_tag %q", rule.ID, rule.OutboundTag)
			}
		}
		if !hasRoutingMatcher(rule) {
			return fmt.Errorf("routing rule %q requires at least one matcher", rule.ID)
		}
		if !validRoutingNetwork(rule.Network) {
			return fmt.Errorf("routing rule %q has invalid network %q", rule.ID, rule.Network)
		}
		if !validRoutingPort(rule.Port) {
			return fmt.Errorf("routing rule %q has invalid port %q", rule.ID, rule.Port)
		}
		if !validRoutingPort(rule.SourcePort) {
			return fmt.Errorf("routing rule %q has invalid source_port %q", rule.ID, rule.SourcePort)
		}
	}
	return nil
}

func ApplyRoutingOverride(values *types.ServerNodeConfigValues, req types.ServerNodeConfigOverride) error {
	if values == nil || req.InheritRoutingRules {
		return nil
	}

	globalRules := NormalizeRoutingRules(values.RoutingRules)
	serverRules := NormalizeRoutingRules(req.RoutingRules)
	switch normalizeRoutingMode(req.RoutingMode) {
	case RoutingModeOverride:
		values.RoutingRules = serverRules
	case RoutingModeAppend:
		values.RoutingRules = append(serverRules, globalRules...)
	default:
		values.RoutingRules = globalRules
	}
	return nil
}

func NodeFacingRoutingRules(rules []types.NodeRoutingRule) []types.NodeRoutingRule {
	normalized := NormalizeRoutingRules(rules)
	result := make([]types.NodeRoutingRule, 0, len(normalized))
	for _, rule := range normalized {
		if !rule.Enabled {
			continue
		}
		result = append(result, rule)
	}
	return result
}

func NormalizeRelayRules(values []types.NodeRelayRule) []types.NodeRelayRule {
	if values == nil {
		return []types.NodeRelayRule{}
	}
	result := make([]types.NodeRelayRule, 0, len(values))
	for _, item := range values {
		rule := types.NodeRelayRule{
			ID:                  strings.TrimSpace(item.ID),
			Enabled:             item.Enabled,
			Sort:                item.Sort,
			Remark:              strings.TrimSpace(item.Remark),
			ListenPort:          item.ListenPort,
			Network:             strings.TrimSpace(item.Network),
			TargetAddress:       strings.TrimSpace(item.TargetAddress),
			TargetPort:          item.TargetPort,
			TargetProtocol:      strings.ToLower(strings.TrimSpace(item.TargetProtocol)),
			TargetSecurity:      strings.ToLower(strings.TrimSpace(item.TargetSecurity)),
			TargetSNI:           strings.TrimSpace(item.TargetSNI),
			TargetTransport:     strings.ToLower(strings.TrimSpace(item.TargetTransport)),
			TargetHost:          strings.TrimSpace(item.TargetHost),
			TargetPath:          strings.TrimSpace(item.TargetPath),
			TargetXHTTPMode:     strings.TrimSpace(item.TargetXHTTPMode),
			TargetXHTTPExtra:    strings.TrimSpace(item.TargetXHTTPExtra),
			TargetUUID:          strings.TrimSpace(item.TargetUUID),
			TargetPassword:      strings.TrimSpace(item.TargetPassword),
			TargetAllowInsecure: item.TargetAllowInsecure,
		}
		if isEmptyRelayRule(rule) {
			continue
		}
		result = append(result, rule)
	}
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].Sort < result[j].Sort
	})
	return result
}

func ValidateRelayRules(rules []types.NodeRelayRule) error {
	listenPorts := map[int]string{}
	for _, rule := range NormalizeRelayRules(rules) {
		if !rule.Enabled {
			continue
		}
		if rule.ListenPort < 1 || rule.ListenPort > 65535 {
			return fmt.Errorf("relay rule %q has invalid listen_port %d", rule.ID, rule.ListenPort)
		}
		if owner, exists := listenPorts[rule.ListenPort]; exists {
			return fmt.Errorf("relay rule %q duplicates listen_port %d used by %q", rule.ID, rule.ListenPort, owner)
		}
		listenPorts[rule.ListenPort] = rule.ID
		if rule.TargetAddress == "" {
			return fmt.Errorf("relay rule %q target_address is required", rule.ID)
		}
		if rule.TargetPort < 1 || rule.TargetPort > 65535 {
			return fmt.Errorf("relay rule %q has invalid target_port %d", rule.ID, rule.TargetPort)
		}
		if !validRelayProtocol(rule.TargetProtocol) {
			return fmt.Errorf("relay rule %q has invalid target_protocol %q", rule.ID, rule.TargetProtocol)
		}
		if !validRoutingNetwork(rule.Network) {
			return fmt.Errorf("relay rule %q has invalid network %q", rule.ID, rule.Network)
		}
	}
	return nil
}

func NodeFacingRelayRules(rules []types.NodeRelayRule) []types.NodeRelayRule {
	normalized := NormalizeRelayRules(rules)
	result := make([]types.NodeRelayRule, 0, len(normalized))
	for _, rule := range normalized {
		if !rule.Enabled {
			continue
		}
		result = append(result, rule)
	}
	return result
}

func unmarshalJSONField[T any](value string, target *T, field string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(value), target); err != nil {
		return errors.Wrapf(err, "unmarshal server node config %s", field)
	}
	return nil
}

func marshalJSONField(value any, field string) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", errors.Wrapf(err, "marshal server node config %s", field)
	}
	return string(data), nil
}

func normalizeStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func ensureDNS(values []types.NodeDNS) []types.NodeDNS {
	if values == nil {
		return []types.NodeDNS{}
	}
	result := make([]types.NodeDNS, 0, len(values))
	for _, item := range values {
		proto := strings.TrimSpace(item.Proto)
		address := strings.TrimSpace(item.Address)
		if proto == "" || address == "" {
			continue
		}
		result = append(result, types.NodeDNS{
			Proto:   proto,
			Address: address,
			Domains: normalizeStrings(item.Domains),
		})
	}
	return result
}

func ensureOutbound(values []types.NodeOutbound) []types.NodeOutbound {
	if values == nil {
		return []types.NodeOutbound{}
	}
	result := make([]types.NodeOutbound, 0, len(values))
	for _, item := range values {
		name := strings.TrimSpace(item.Name)
		protocol := strings.TrimSpace(item.Protocol)
		rules := normalizeStrings(item.Rules)
		if name == "" || protocol == "" {
			continue
		}
		result = append(result, types.NodeOutbound{
			Name:                 name,
			Protocol:             protocol,
			Address:              strings.TrimSpace(item.Address),
			Port:                 item.Port,
			User:                 strings.TrimSpace(item.User),
			Password:             item.Password,
			UUID:                 strings.TrimSpace(item.UUID),
			Cipher:               strings.TrimSpace(item.Cipher),
			Security:             strings.TrimSpace(item.Security),
			SNI:                  strings.TrimSpace(item.SNI),
			AllowInsecure:        item.AllowInsecure,
			Fingerprint:          strings.TrimSpace(item.Fingerprint),
			Transport:            strings.TrimSpace(item.Transport),
			Host:                 strings.TrimSpace(item.Host),
			Path:                 strings.TrimSpace(item.Path),
			ServiceName:          strings.TrimSpace(item.ServiceName),
			Flow:                 strings.TrimSpace(item.Flow),
			UoT:                  item.UoT,
			UoTVersion:           item.UoTVersion,
			CongestionController: strings.TrimSpace(item.CongestionController),
			UDPStream:            item.UDPStream,
			ReduceRtt:            item.ReduceRtt,
			Heartbeat:            item.Heartbeat,
			RealityPublicKey:     strings.TrimSpace(item.RealityPublicKey),
			RealityShortId:       strings.TrimSpace(item.RealityShortId),
			SpiderX:              strings.TrimSpace(item.SpiderX),
			Settings:             strings.TrimSpace(item.Settings),
			StreamSettings:       strings.TrimSpace(item.StreamSettings),
			Rules:                rules,
		})
	}
	return result
}

func stringPtr(value string) *string {
	return &value
}

func configRoutingRules(values []config.NodeRoutingRule) []types.NodeRoutingRule {
	result := make([]types.NodeRoutingRule, 0, len(values))
	for _, rule := range values {
		result = append(result, types.NodeRoutingRule{
			ID:          rule.ID,
			Enabled:     rule.Enabled,
			Sort:        rule.Sort,
			Remark:      rule.Remark,
			SourceIP:    rule.SourceIP,
			SourcePort:  rule.SourcePort,
			VlessRoute:  rule.VlessRoute,
			InboundTags: rule.InboundTags,
			OutboundTag: rule.OutboundTag,
			BalancerTag: rule.BalancerTag,
			Domain:      rule.Domain,
			IP:          rule.IP,
			User:        rule.User,
			Port:        rule.Port,
			Protocol:    rule.Protocol,
			Attrs:       rule.Attrs,
			Network:     rule.Network,
		})
	}
	return NormalizeRoutingRules(result)
}

func configRelayRules(values []config.NodeRelayRule) []types.NodeRelayRule {
	result := make([]types.NodeRelayRule, 0, len(values))
	for _, rule := range values {
		result = append(result, types.NodeRelayRule{
			ID:                  rule.ID,
			Enabled:             rule.Enabled,
			Sort:                rule.Sort,
			Remark:              rule.Remark,
			ListenPort:          rule.ListenPort,
			Network:             rule.Network,
			TargetAddress:       rule.TargetAddress,
			TargetPort:          rule.TargetPort,
			TargetProtocol:      rule.TargetProtocol,
			TargetSecurity:      rule.TargetSecurity,
			TargetSNI:           rule.TargetSNI,
			TargetTransport:     rule.TargetTransport,
			TargetHost:          rule.TargetHost,
			TargetPath:          rule.TargetPath,
			TargetXHTTPMode:     rule.TargetXHTTPMode,
			TargetXHTTPExtra:    rule.TargetXHTTPExtra,
			TargetUUID:          rule.TargetUUID,
			TargetPassword:      rule.TargetPassword,
			TargetAllowInsecure: rule.TargetAllowInsecure,
		})
	}
	return NormalizeRelayRules(result)
}

func isEmptyRoutingRule(rule types.NodeRoutingRule) bool {
	return rule.ID == "" &&
		!rule.Enabled &&
		rule.Sort == 0 &&
		rule.Remark == "" &&
		len(rule.SourceIP) == 0 &&
		rule.SourcePort == "" &&
		rule.VlessRoute == "" &&
		len(rule.InboundTags) == 0 &&
		rule.OutboundTag == "" &&
		rule.BalancerTag == "" &&
		!hasRoutingMatcher(rule)
}

func hasRoutingMatcher(rule types.NodeRoutingRule) bool {
	return len(rule.SourceIP) > 0 ||
		rule.SourcePort != "" ||
		len(rule.InboundTags) > 0 ||
		len(rule.Domain) > 0 ||
		len(rule.IP) > 0 ||
		len(rule.User) > 0 ||
		rule.Port != "" ||
		rule.Protocol != "" ||
		rule.Attrs != "" ||
		rule.Network != ""
}

func isEmptyRelayRule(rule types.NodeRelayRule) bool {
	return rule.ID == "" &&
		!rule.Enabled &&
		rule.Sort == 0 &&
		rule.Remark == "" &&
		rule.ListenPort == 0 &&
		rule.Network == "" &&
		rule.TargetAddress == "" &&
		rule.TargetPort == 0 &&
		rule.TargetProtocol == "" &&
		rule.TargetSecurity == "" &&
		rule.TargetSNI == "" &&
		rule.TargetTransport == "" &&
		rule.TargetHost == "" &&
		rule.TargetPath == "" &&
		rule.TargetUUID == "" &&
		rule.TargetPassword == ""
}

func validRelayProtocol(value string) bool {
	switch value {
	case "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "anytls":
		return true
	default:
		return false
	}
}

func validRoutingNetwork(value string) bool {
	switch value {
	case "", "tcp", "udp", "tcp,udp":
		return true
	default:
		return false
	}
}

var routingPortPartPattern = regexp.MustCompile(`^\d{1,5}(-\d{1,5})?$`)

func validRoutingPort(value string) bool {
	if value == "" {
		return true
	}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if !routingPortPartPattern.MatchString(part) {
			return false
		}
		bounds := strings.Split(part, "-")
		start, err := strconv.Atoi(bounds[0])
		if err != nil || start < 1 || start > 65535 {
			return false
		}
		if len(bounds) == 2 {
			end, err := strconv.Atoi(bounds[1])
			if err != nil || end < start || end > 65535 {
				return false
			}
		}
	}
	return true
}

func normalizeRoutingMode(value string) string {
	switch strings.TrimSpace(value) {
	case RoutingModeAppend:
		return RoutingModeAppend
	case RoutingModeOverride:
		return RoutingModeOverride
	default:
		return RoutingModeInherit
	}
}

func stringValue(value *string, fallback string) string {
	if value == nil {
		return fallback
	}
	return *value
}
