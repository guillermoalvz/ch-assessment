package scanner

import "sort"

const publicIPv4 = "0.0.0.0/0"

// Port is always a string: a single port, a range, or "all".
// ICMP uses type/code rather than transport ports; -1 means any type/code.
type InsecureRule struct {
	Name         string   `json:"name,omitempty"`
	Protocol     string   `json:"protocol"`
	Port         string   `json:"port"`
	Source       string   `json:"source"`
	SourcePrefix string   `json:"source_prefix,omitempty"`
	SourcePorts  []string `json:"source_ports,omitempty"`
	Destinations []string `json:"destinations,omitempty"`
	Priority     *int32   `json:"priority,omitempty"`
	ICMPType     *int32   `json:"icmp_type,omitempty"`
	ICMPCode     *int32   `json:"icmp_code,omitempty"`
}

type SecurityGroupFinding struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Region        string         `json:"region"`
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

type FirewallFinding struct {
	Name          string         `json:"name"`
	Network       string         `json:"network"`
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

type NSGFinding struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

type AWSReport struct {
	Regions        []string               `json:"regions"`
	SecurityGroups []SecurityGroupFinding `json:"security_groups"`
}

type GCPReport struct {
	Project       string            `json:"project"`
	FirewallRules []FirewallFinding `json:"firewall_rules"`
}

type AzureReport struct {
	Subscription string       `json:"subscription"`
	NSGs         []NSGFinding `json:"nsgs"`
}

type ScanError struct {
	Provider string `json:"provider"`
	Scope    string `json:"scope,omitempty"`
	Message  string `json:"message"`
}

type Report struct {
	AWS    *AWSReport   `json:"aws,omitempty"`
	GCP    *GCPReport   `json:"gcp,omitempty"`
	Azure  *AzureReport `json:"azure,omitempty"`
	Errors []ScanError  `json:"errors,omitempty"`
}

func sortRules(rules []InsecureRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		a, b := rules[i], rules[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.SourcePrefix < b.SourcePrefix
	})
}

// Sort orders findings consistently across providers.
func (r *Report) Sort() {
	if r.AWS != nil {
		sort.Strings(r.AWS.Regions)
		sort.Slice(r.AWS.SecurityGroups, func(i, j int) bool {
			a, b := r.AWS.SecurityGroups[i], r.AWS.SecurityGroups[j]
			if a.Region != b.Region {
				return a.Region < b.Region
			}
			return a.ID < b.ID
		})
		for _, group := range r.AWS.SecurityGroups {
			sortRules(group.InsecureRules)
		}
	}
	if r.GCP != nil {
		sort.Slice(r.GCP.FirewallRules, func(i, j int) bool {
			return r.GCP.FirewallRules[i].Name < r.GCP.FirewallRules[j].Name
		})
		for _, firewall := range r.GCP.FirewallRules {
			sortRules(firewall.InsecureRules)
		}
	}
	if r.Azure != nil {
		sort.Slice(r.Azure.NSGs, func(i, j int) bool { return r.Azure.NSGs[i].ID < r.Azure.NSGs[j].ID })
		for _, nsg := range r.Azure.NSGs {
			sortRules(nsg.InsecureRules)
		}
	}
}
