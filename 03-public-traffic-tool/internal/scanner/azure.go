package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v9"
)

func value[T any](p *T) (v T) {
	if p != nil {
		return *p
	}
	return v
}

func stringsFromPointers(single *string, multiple []*string) []string {
	var values []string
	seen := make(map[string]bool)
	for _, p := range append([]*string{single}, multiple...) {
		if s := value(p); s != "" && !seen[s] {
			values = append(values, s)
			seen[s] = true
		}
	}
	return values
}

func azureRules(nsg *armnetwork.SecurityGroup) []InsecureRule {
	if nsg == nil || nsg.Properties == nil {
		return nil
	}
	var findings []InsecureRule
	// Defaults are included for completeness (the standard inbound defaults
	// do not permit Internet traffic).
	rules := append([]*armnetwork.SecurityRule{}, nsg.Properties.SecurityRules...)
	rules = append(rules, nsg.Properties.DefaultSecurityRules...)
	for _, rule := range rules {
		if rule == nil || rule.Properties == nil {
			continue
		}
		p := rule.Properties
		if value(p.Direction) != armnetwork.SecurityRuleDirectionInbound || value(p.Access) != armnetwork.SecurityRuleAccessAllow {
			continue
		}
		var publicSource string
		for _, source := range stringsFromPointers(p.SourceAddressPrefix, p.SourceAddressPrefixes) {
			if source == publicIPv4 || source == "*" || strings.EqualFold(source, "Any") || strings.EqualFold(source, "Internet") {
				publicSource = source
				break
			}
		}
		if publicSource == "" {
			continue
		}
		ports := stringsFromPointers(p.DestinationPortRange, p.DestinationPortRanges)
		for _, port := range ports {
			protocol := strings.ToLower(string(value(p.Protocol)))
			if protocol == "*" {
				protocol = "all"
			}
			if port == "*" {
				port = "all"
			}
			finding := InsecureRule{
				Name: value(rule.Name), Protocol: protocol, Port: port, Source: publicIPv4,
				Priority: p.Priority, SourcePorts: stringsFromPointers(p.SourcePortRange, p.SourcePortRanges),
				Destinations: stringsFromPointers(p.DestinationAddressPrefix, p.DestinationAddressPrefixes),
			}
			if publicSource != publicIPv4 {
				finding.SourcePrefix = publicSource
			}
			findings = append(findings, finding)
		}
	}
	return findings
}

func collectAzure(ctx context.Context, client *armnetwork.SecurityGroupsClient) ([]NSGFinding, error) {
	findings := make([]NSGFinding, 0)
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return findings, err
		}
		for _, nsg := range page.Value {
			if rules := azureRules(nsg); len(rules) > 0 {
				findings = append(findings, NSGFinding{ID: value(nsg.ID), Name: value(nsg.Name), InsecureRules: rules})
			}
		}
	}
	return findings, nil
}

// ScanAzure lists public inbound allows in Azure network security groups.
func ScanAzure(ctx context.Context, opts Options) (AzureReport, []ScanError) {
	result := AzureReport{Subscription: opts.AzureSubscription, NSGs: make([]NSGFinding, 0)}
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err == nil {
		var client *armnetwork.SecurityGroupsClient
		client, err = armnetwork.NewSecurityGroupsClient(opts.AzureSubscription, credential, nil)
		if err == nil {
			result.NSGs, err = collectAzure(ctx, client)
		}
	}
	if err != nil {
		return result, []ScanError{{Provider: "azure", Scope: opts.AzureSubscription, Message: fmt.Sprintf("list NSGs: %v", err)}}
	}
	return result, nil
}
