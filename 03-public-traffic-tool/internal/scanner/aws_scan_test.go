package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAWSRegionDiscoveryAndFailureIsolation(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicit=%v", explicit), func(t *testing.T) {
			discoveryCalls, groupCalls := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				w.Header().Set("Content-Type", "text/xml")
				switch r.Form.Get("Action") {
				case "DescribeRegions":
					discoveryCalls++
					if r.Form.Get("AllRegions") != "false" {
						t.Errorf("should discover enabled regions only: %v", r.Form)
					}
					fmt.Fprint(w, `<DescribeRegionsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><regionInfo><item><regionName>us-east-1</regionName></item><item><regionName>eu-west-1</regionName></item></regionInfo></DescribeRegionsResponse>`)
				case "DescribeSecurityGroups":
					groupCalls++
					if strings.Contains(r.Header.Get("Authorization"), "/eu-west-1/") {
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprint(w, `<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>denied in eu-west-1</Message></Error></Errors><RequestID>test</RequestID></Response>`)
						return
					}
					if !strings.Contains(r.Header.Get("Authorization"), "/us-east-1/") {
						t.Errorf("unexpected regional signature: %s", r.Header.Get("Authorization"))
					}
					fmt.Fprint(w, `<DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><securityGroupInfo><item><groupId>sg-public</groupId><groupName>public</groupName><ipPermissions><item><ipProtocol>-1</ipProtocol><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item></ipPermissions></item></securityGroupInfo></DescribeSecurityGroupsResponse>`)
				default:
					t.Errorf("unexpected API action: %v", r.Form)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer server.Close()
			// Keep all SDK requests local with synthetic credentials and empty
			// config files, independent of the developer's AWS configuration.
			t.Setenv("AWS_ACCESS_KEY_ID", "test-access-key")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
			t.Setenv("AWS_SESSION_TOKEN", "")
			t.Setenv("AWS_ENDPOINT_URL_EC2", server.URL)
			t.Setenv("AWS_CONFIG_FILE", t.TempDir()+"/config")
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", t.TempDir()+"/credentials")
			t.Setenv("AWS_PROFILE", "")
			t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
			opts := Options{AWSRegion: "us-east-1"}
			if explicit {
				opts.AWSRegions = []string{"us-east-1", "eu-west-1"}
			}
			got, scanErrors := ScanAWS(context.Background(), opts)
			wantDiscovery := 1
			if explicit {
				wantDiscovery = 0
			}
			if discoveryCalls != wantDiscovery || groupCalls != 2 || len(got.Regions) != 2 || len(got.SecurityGroups) != 1 || len(scanErrors) != 1 {
				t.Fatalf("result %+v errors %+v discovery %d groups %d", got, scanErrors, discoveryCalls, groupCalls)
			}
			if got.SecurityGroups[0].Region != "us-east-1" || scanErrors[0].Scope != "eu-west-1" {
				t.Fatalf("regional results incorrect: %+v, %+v", got, scanErrors)
			}
		})
	}
}
