package scanner

import (
	"reflect"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v9"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"google.golang.org/api/compute/v1"
)

func ptr[T any](v T) *T { return &v }

func TestAWSRules(t *testing.T) {
	for _, tc := range []struct {
		name, protocol string
		from, to       int32
		want           InsecureRule
	}{
		{"single TCP", "tcp", 8080, 8080, InsecureRule{Protocol: "tcp", Port: "8080", Source: publicIPv4}},
		{"UDP", "udp", 123, 123, InsecureRule{Protocol: "udp", Port: "123", Source: publicIPv4}},
		{"numeric TCP and range", "6", 80, 443, InsecureRule{Protocol: "tcp", Port: "80-443", Source: publicIPv4}},
		{"numeric UDP", "17", 0, 65535, InsecureRule{Protocol: "udp", Port: "0-65535", Source: publicIPv4}},
		{"all protocols", "-1", 0, 0, InsecureRule{Protocol: "all", Port: "all", Source: publicIPv4}},
		{"all ICMP", "icmp", -1, -1, InsecureRule{Protocol: "icmp", Port: "all", Source: publicIPv4, ICMPType: ptr(int32(-1)), ICMPCode: ptr(int32(-1))}},
		{"ICMP echo", "1", 8, 0, InsecureRule{Protocol: "icmp", Port: "all", Source: publicIPv4, ICMPType: ptr(int32(8)), ICMPCode: ptr(int32(0))}},
		{"other protocol", "50", 0, 0, InsecureRule{Protocol: "50", Port: "all", Source: publicIPv4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			group := types.SecurityGroup{IpPermissions: []types.IpPermission{{
				IpProtocol: ptr(tc.protocol), FromPort: ptr(tc.from), ToPort: ptr(tc.to),
				IpRanges: []types.IpRange{{CidrIp: ptr("10.0.0.0/8")}, {CidrIp: ptr(publicIPv4)}},
			}}}
			if got := awsRules(group); !reflect.DeepEqual(got, []InsecureRule{tc.want}) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
	t.Run("private ingress and public egress excluded", func(t *testing.T) {
		group := types.SecurityGroup{
			IpPermissions: []types.IpPermission{
				{IpProtocol: ptr("tcp"), IpRanges: []types.IpRange{{CidrIp: ptr("10.0.0.0/8")}, {}}},
				{IpProtocol: ptr("-1"), Ipv6Ranges: []types.Ipv6Range{{CidrIpv6: ptr("::/0")}}},
			},
			IpPermissionsEgress: []types.IpPermission{{IpProtocol: ptr("-1"), IpRanges: []types.IpRange{{CidrIp: ptr(publicIPv4)}}}},
		}
		if got := awsRules(group); len(got) != 0 {
			t.Fatalf("unexpected findings: %+v", got)
		}
	})
}

func TestGCPRules(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*compute.Firewall)
		want   []InsecureRule
	}{
		{"public single port", func(f *compute.Firewall) {}, []InsecureRule{{Protocol: "tcp", Port: "22", Source: publicIPv4}}},
		{"implicit source and direction", func(f *compute.Firewall) { f.SourceRanges = nil; f.Direction = "" }, []InsecureRule{{Protocol: "tcp", Port: "22", Source: publicIPv4}}},
		{"multiple protocols and ranges", func(f *compute.Firewall) {
			f.Allowed = []*compute.FirewallAllowed{{IPProtocol: "udp", Ports: []string{"53", "100-200"}}, {IPProtocol: "icmp"}, {IPProtocol: "all"}, nil}
		}, []InsecureRule{{Protocol: "udp", Port: "53", Source: publicIPv4}, {Protocol: "udp", Port: "100-200", Source: publicIPv4}, {Protocol: "icmp", Port: "all", Source: publicIPv4}, {Protocol: "all", Port: "all", Source: publicIPv4}}},
		{"disabled", func(f *compute.Firewall) { f.Disabled = true }, nil},
		{"egress", func(f *compute.Firewall) { f.Direction = "EGRESS" }, nil},
		{"deny only", func(f *compute.Firewall) { f.Allowed = nil; f.Denied = []*compute.FirewallDenied{{IPProtocol: "all"}} }, nil},
		{"private", func(f *compute.Firewall) { f.SourceRanges = []string{"10.0.0.0/8"} }, nil},
		{"IPv6 only", func(f *compute.Firewall) { f.SourceRanges = []string{"::/0"} }, nil},
		{"source tags only", func(f *compute.Firewall) { f.SourceRanges = nil; f.SourceTags = []string{"trusted"} }, nil},
		{"source accounts only", func(f *compute.Firewall) {
			f.SourceRanges = nil
			f.SourceServiceAccounts = []string{"trusted@example.com"}
		}, nil},
		{"tags do not narrow explicit public range", func(f *compute.Firewall) { f.SourceTags = []string{"trusted"} }, []InsecureRule{{Protocol: "tcp", Port: "22", Source: publicIPv4}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			firewall := &compute.Firewall{Direction: "INGRESS", SourceRanges: []string{"10.0.0.0/8", publicIPv4}, Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}}}
			tc.change(firewall)
			if got := gcpRules(firewall); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
	if got := gcpRules(nil); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestAzureRules(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*armnetwork.SecurityRulePropertiesFormat)
		ports  []string
	}{
		{"public CIDR", func(p *armnetwork.SecurityRulePropertiesFormat) {}, []string{"443"}},
		{"wildcard", func(p *armnetwork.SecurityRulePropertiesFormat) {
			p.SourceAddressPrefix = ptr("*")
			p.Protocol = ptr(armnetwork.SecurityRuleProtocolAsterisk)
			p.DestinationPortRange = ptr("*")
		}, []string{"all"}},
		{"Any", func(p *armnetwork.SecurityRulePropertiesFormat) { p.SourceAddressPrefix = ptr("Any") }, []string{"443"}},
		{"Internet tag", func(p *armnetwork.SecurityRulePropertiesFormat) { p.SourceAddressPrefix = ptr("Internet") }, []string{"443"}},
		{"augmented sources and ports", func(p *armnetwork.SecurityRulePropertiesFormat) {
			p.SourceAddressPrefix = nil
			p.SourceAddressPrefixes = []*string{ptr("10.0.0.0/8"), nil, ptr(publicIPv4)}
			p.DestinationPortRange = nil
			p.DestinationPortRanges = []*string{ptr("80"), ptr("100-200")}
		}, []string{"80", "100-200"}},
		{"deny", func(p *armnetwork.SecurityRulePropertiesFormat) { p.Access = ptr(armnetwork.SecurityRuleAccessDeny) }, nil},
		{"outbound", func(p *armnetwork.SecurityRulePropertiesFormat) {
			p.Direction = ptr(armnetwork.SecurityRuleDirectionOutbound)
		}, nil},
		{"private", func(p *armnetwork.SecurityRulePropertiesFormat) { p.SourceAddressPrefix = ptr("10.0.0.0/8") }, nil},
		{"VirtualNetwork tag", func(p *armnetwork.SecurityRulePropertiesFormat) { p.SourceAddressPrefix = ptr("VirtualNetwork") }, nil},
		{"IPv6 only", func(p *armnetwork.SecurityRulePropertiesFormat) { p.SourceAddressPrefix = ptr("::/0") }, nil},
		{"no properties", func(p *armnetwork.SecurityRulePropertiesFormat) { *p = armnetwork.SecurityRulePropertiesFormat{} }, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &armnetwork.SecurityRulePropertiesFormat{
				Direction: ptr(armnetwork.SecurityRuleDirectionInbound), Access: ptr(armnetwork.SecurityRuleAccessAllow),
				Protocol: ptr(armnetwork.SecurityRuleProtocolTCP), SourceAddressPrefix: ptr(publicIPv4),
				DestinationPortRange: ptr("443"), SourcePortRange: ptr("1024-65535"), DestinationAddressPrefix: ptr("10.0.0.4"), Priority: ptr(int32(100)),
			}
			tc.change(p)
			nsg := &armnetwork.SecurityGroup{Properties: &armnetwork.SecurityGroupPropertiesFormat{SecurityRules: []*armnetwork.SecurityRule{nil, {}, {Name: ptr("rule"), Properties: p}}}}
			got := azureRules(nsg)
			if len(got) != len(tc.ports) {
				t.Fatalf("got %+v, want ports %v", got, tc.ports)
			}
			for i, rule := range got {
				if rule.Port != tc.ports[i] || rule.Source != publicIPv4 || rule.Name != "rule" || value(rule.Priority) != 100 {
					t.Fatalf("unexpected rule: %+v", rule)
				}
				if !reflect.DeepEqual(rule.SourcePorts, []string{"1024-65535"}) || !reflect.DeepEqual(rule.Destinations, []string{"10.0.0.4"}) {
					t.Fatalf("constraints lost: %+v", rule)
				}
				if tc.name == "wildcard" && (rule.Protocol != "all" || rule.SourcePrefix != "*") {
					t.Fatalf("wildcards not normalized: %+v", rule)
				}
			}
		})
	}
	if len(azureRules(nil)) != 0 || len(azureRules(&armnetwork.SecurityGroup{})) != 0 {
		t.Fatal("nil resources should have no findings")
	}
}
