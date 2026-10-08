package scanner

import (
	"context"
	"fmt"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

func gcpRules(firewall *compute.Firewall) []InsecureRule {
	if firewall == nil || firewall.Disabled || (firewall.Direction != "" && firewall.Direction != "INGRESS") {
		return nil
	}
	public := false
	for _, source := range firewall.SourceRanges {
		if source == publicIPv4 {
			public = true
			break
		}
	}
	// An omitted source defaults to 0.0.0.0/0 only when there are no
	// source tags or source service accounts restricting the source.
	if len(firewall.SourceRanges) == 0 && len(firewall.SourceTags) == 0 && len(firewall.SourceServiceAccounts) == 0 {
		public = true
	}
	if !public {
		return nil
	}
	var findings []InsecureRule
	for _, allowed := range firewall.Allowed {
		if allowed == nil {
			continue
		}
		ports := allowed.Ports
		if len(ports) == 0 {
			ports = []string{"all"}
		}
		for _, port := range ports {
			findings = append(findings, InsecureRule{Protocol: allowed.IPProtocol, Port: port, Source: publicIPv4})
		}
	}
	return findings
}

func collectGCP(ctx context.Context, client *compute.Service, project string) ([]FirewallFinding, error) {
	findings := make([]FirewallFinding, 0)
	err := client.Firewalls.List(project).Pages(ctx, func(page *compute.FirewallList) error {
		for _, firewall := range page.Items {
			if rules := gcpRules(firewall); len(rules) > 0 {
				findings = append(findings, FirewallFinding{Name: firewall.Name, Network: firewall.Network, InsecureRules: rules})
			}
		}
		return nil
	})
	return findings, err
}

// ScanGCP lists public inbound allows in GCP firewall rules.
func ScanGCP(ctx context.Context, opts Options) (GCPReport, []ScanError) {
	result := GCPReport{Project: opts.GCPProject, FirewallRules: make([]FirewallFinding, 0)}
	client, err := compute.NewService(ctx, option.WithScopes(compute.ComputeReadonlyScope))
	if err == nil {
		result.FirewallRules, err = collectGCP(ctx, client, opts.GCPProject)
	}
	if err != nil {
		return result, []ScanError{{Provider: "gcp", Scope: opts.GCPProject, Message: fmt.Sprintf("list firewall rules: %v", err)}}
	}
	return result, nil
}
