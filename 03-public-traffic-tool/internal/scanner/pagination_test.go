package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v9"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

type fakeEC2 struct {
	t     *testing.T
	calls int
	fail  bool
}

func (f *fakeEC2) DescribeSecurityGroups(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	f.calls++
	if f.calls == 2 {
		if value(input.NextToken) != "next" {
			f.t.Fatalf("missing pagination token: %+v", input)
		}
		if f.fail {
			return nil, errors.New("page two failed")
		}
	}
	page := &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []types.SecurityGroup{{
		GroupId: ptr(fmt.Sprintf("sg-%d", f.calls)), GroupName: ptr("public"),
		IpPermissions: []types.IpPermission{{IpProtocol: ptr("-1"), IpRanges: []types.IpRange{{CidrIp: ptr(publicIPv4)}}}},
	}}}
	if f.calls == 1 {
		page.NextToken = ptr("next")
	}
	return page, nil
}

func TestAWSPagination(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail=%v", fail), func(t *testing.T) {
			client := &fakeEC2{t: t, fail: fail}
			got, err := collectAWS(context.Background(), client, "eu-west-1")
			want := 2
			if fail {
				want = 1
			}
			if (err != nil) != fail || len(got) != want || client.calls != 2 || got[0].Region != "eu-west-1" {
				t.Fatalf("got %+v, err %v, calls %d", got, err, client.calls)
			}
		})
	}
}

func TestGCPPagination(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail=%v", fail), func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/projects/project/global/firewalls" || (calls == 2 && r.URL.Query().Get("pageToken") != "next") {
					t.Errorf("unexpected request %s", r.URL)
				}
				w.Header().Set("Content-Type", "application/json")
				if calls == 2 && fail {
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprint(w, `{"error":{"code":403,"message":"denied"}}`)
					return
				}
				page := compute.FirewallList{Items: []*compute.Firewall{{Name: fmt.Sprintf("rule-%d", calls), Network: "default", Allowed: []*compute.FirewallAllowed{{IPProtocol: "icmp"}}}}}
				if calls == 1 {
					page.NextPageToken = "next"
				}
				json.NewEncoder(w).Encode(page)
			}))
			defer server.Close()
			client, err := compute.NewService(context.Background(), option.WithEndpoint(server.URL+"/"), option.WithoutAuthentication())
			if err != nil {
				t.Fatal(err)
			}
			got, err := collectGCP(context.Background(), client, "project")
			want := 2
			if fail {
				want = 1
			}
			if (err != nil) != fail || len(got) != want || calls != 2 {
				t.Fatalf("got %+v, err %v, calls %d", got, err, calls)
			}
		})
	}
}

type fakeAzureCredential struct{}

func (fakeAzureCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestAzurePagination(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail=%v", fail), func(t *testing.T) {
			calls := 0
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls == 2 && r.URL.Path != "/next" {
					t.Errorf("unexpected next link: %s", r.URL)
				}
				if calls == 1 && r.URL.Path != "/subscriptions/sub/providers/Microsoft.Network/networkSecurityGroups" {
					t.Errorf("unexpected scope: %s", r.URL)
				}
				w.Header().Set("Content-Type", "application/json")
				if calls == 2 && fail {
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprint(w, `{"error":{"code":"AuthorizationFailed","message":"denied"}}`)
					return
				}
				page := armnetwork.SecurityGroupListResult{Value: []*armnetwork.SecurityGroup{{ID: ptr(fmt.Sprintf("nsg-%d", calls)), Name: ptr("public"), Properties: &armnetwork.SecurityGroupPropertiesFormat{
					SecurityRules: []*armnetwork.SecurityRule{{Name: ptr("allow"), Properties: &armnetwork.SecurityRulePropertiesFormat{
						Direction: ptr(armnetwork.SecurityRuleDirectionInbound), Access: ptr(armnetwork.SecurityRuleAccessAllow), Protocol: ptr(armnetwork.SecurityRuleProtocolAsterisk), SourceAddressPrefix: ptr("*"), DestinationPortRange: ptr("*"),
					}}},
				}}}}
				if calls == 1 {
					page.NextLink = ptr(server.URL + "/next")
				}
				json.NewEncoder(w).Encode(page)
			}))
			defer server.Close()
			client, err := armnetwork.NewSecurityGroupsClient("sub", fakeAzureCredential{}, &arm.ClientOptions{ClientOptions: azcore.ClientOptions{
				Transport: server.Client(), Retry: policy.RetryOptions{MaxRetries: -1},
				Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{cloud.ResourceManager: {Endpoint: server.URL, Audience: server.URL}}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			got, err := collectAzure(context.Background(), client)
			want := 2
			if fail {
				want = 1
			}
			if (err != nil) != fail || len(got) != want || calls != 2 {
				t.Fatalf("got %+v, err %v, calls %d", got, err, calls)
			}
		})
	}
}
