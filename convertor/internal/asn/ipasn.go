package asn

import (
	"context"

	"github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/srsc/adapter"
)

func ConvertIPASNToIPCIDR(ctx context.Context, rules []adapter.Rule) ([]adapter.Rule, error) {
	if len(rules) == 0 || !containsIPASN(rules) {
		return rules, nil
	}

	resolver := NewASNResolver()
	if err := walkRules(rules, func(rule *adapter.Rule) error {
		if rule.Type != constant.RuleTypeDefault {
			return nil
		}
		return convertDefaultRuleIPASN(ctx, resolver, &rule.DefaultOptions)
	}); err != nil {
		return nil, E.Cause(err, "convert rule IP-ASN")
	}

	return rules, nil
}

func convertDefaultRuleIPASN(ctx context.Context, resolver *ASNResolver, rule *adapter.DefaultRule) error {
	if err := resolveAndAppend(ctx, resolver, &rule.IPASN, &rule.IPCIDR); err != nil {
		return err
	}
	return resolveAndAppend(ctx, resolver, &rule.SourceIPASN, &rule.SourceIPCIDR)
}

func resolveAndAppend(ctx context.Context, resolver *ASNResolver, source *[]string, destination *badoption.Listable[string]) error {
	if len(*source) == 0 {
		return nil
	}
	prefixes, err := resolver.ResolveASNs(ctx, *source)
	if err != nil {
		return err
	}
	if len(prefixes) > 0 {
		*destination = append(*destination, prefixes...)
	}
	*source = nil
	return nil
}

func containsIPASN(rules []adapter.Rule) bool {
	for i := range rules {
		if ruleContainsIPASN(&rules[i]) {
			return true
		}
	}
	return false
}

func ruleContainsIPASN(rule *adapter.Rule) bool {
	switch rule.Type {
	case constant.RuleTypeDefault:
		return len(rule.DefaultOptions.IPASN) > 0 || len(rule.DefaultOptions.SourceIPASN) > 0
	case constant.RuleTypeLogical:
		for i := range rule.LogicalOptions.Rules {
			if ruleContainsIPASN(&rule.LogicalOptions.Rules[i]) {
				return true
			}
		}
	}
	return false
}

func walkRules(rules []adapter.Rule, fn func(*adapter.Rule) error) error {
	if len(rules) == 0 {
		return nil
	}
	stack := make([]*adapter.Rule, 0, len(rules))
	for i := range rules {
		stack = append(stack, &rules[i])
	}
	for len(stack) > 0 {
		idx := len(stack) - 1
		rule := stack[idx]
		stack = stack[:idx]
		if err := fn(rule); err != nil {
			return err
		}
		if rule.Type == constant.RuleTypeLogical {
			for i := range rule.LogicalOptions.Rules {
				stack = append(stack, &rule.LogicalOptions.Rules[i])
			}
		}
	}
	return nil
}
