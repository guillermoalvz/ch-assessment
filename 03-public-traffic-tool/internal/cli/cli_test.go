package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/ch-assessment/public-traffic-tool/internal/scanner"
)

func TestOptionValidation(t *testing.T) {
	t.Setenv("GOOGLE_CLOUD_PROJECT", "")
	t.Setenv("AZURE_SUBSCRIPTION_ID", "")
	for _, args := range [][]string{
		{}, {"-providers=unknown"}, {"-providers=aws,"}, {"-providers="},
		{"-providers=gcp"}, {"-providers=azure"}, {"-providers=aws", "-timeout=0s"},
		{"-providers=aws", "-timeout=-1s"}, {"-providers=aws", "-aws-regions=us-east-1,"},
		{"-providers=aws", "unexpected"}, {"-invalid-flag"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), args, &stdout, &stderr, scanners{}); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("code %d stdout %q stderr %q", code, &stdout, &stderr)
			}
		})
	}
	t.Setenv("GOOGLE_CLOUD_PROJECT", "project")
	t.Setenv("AZURE_SUBSCRIPTION_ID", "subscription")
	opts, err := parseOptions([]string{"-providers=aws, gcp,azure,aws", "-aws-regions=us-east-1,eu-west-1,us-east-1"}, io.Discard)
	if err != nil || len(opts.providers) != 3 || len(opts.AWSRegions) != 2 || opts.GCPProject != "project" || opts.AzureSubscription != "subscription" {
		t.Fatalf("got %+v, err %v", opts, err)
	}
}

func TestJSONAndPartialFailures(t *testing.T) {
	var calls []string
	clients := scanners{
		aws: func(ctx context.Context, _ scanner.Options) (scanner.AWSReport, []scanner.ScanError) {
			calls = append(calls, "aws")
			if _, ok := ctx.Deadline(); !ok {
				t.Error("missing scan deadline")
			}
			return scanner.AWSReport{Regions: []string{"eu-west-1"}, SecurityGroups: []scanner.SecurityGroupFinding{
				{ID: "sg-z", Region: "eu-west-1", InsecureRules: []scanner.InsecureRule{{Protocol: "tcp", Port: "8080", Source: "0.0.0.0/0"}}},
				{ID: "sg-a", Region: "eu-west-1", InsecureRules: []scanner.InsecureRule{{Protocol: "all", Port: "all", Source: "0.0.0.0/0"}}},
			}}, []scanner.ScanError{{Provider: "aws", Scope: "eu-west-1", Message: "page failed"}}
		},
		gcp: func(_ context.Context, opts scanner.Options) (scanner.GCPReport, []scanner.ScanError) {
			calls = append(calls, "gcp")
			return scanner.GCPReport{Project: opts.GCPProject, FirewallRules: []scanner.FirewallFinding{}}, nil
		},
		azure: func(_ context.Context, opts scanner.Options) (scanner.AzureReport, []scanner.ScanError) {
			calls = append(calls, "azure")
			return scanner.AzureReport{Subscription: opts.AzureSubscription, NSGs: []scanner.NSGFinding{}}, nil
		},
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-gcp-project=project", "-azure-subscription=sub"}, &stdout, &stderr, clients)
	var result scanner.Report
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if code != 1 || len(result.Errors) != 1 || !reflect.DeepEqual(calls, []string{"aws", "gcp", "azure"}) || result.AWS.SecurityGroups[0].ID != "sg-a" {
		t.Fatalf("code %d result %+v calls %v", code, result, calls)
	}
	if !strings.Contains(stdout.String(), `"firewall_rules": []`) || !strings.Contains(stdout.String(), `"nsgs": []`) || !strings.Contains(stderr.String(), "incomplete") {
		t.Fatalf("stdout %q stderr %q", &stdout, &stderr)
	}
}

func TestSingleProviderAndFindingsExitSuccess(t *testing.T) {
	clients := scanners{gcp: func(_ context.Context, opts scanner.Options) (scanner.GCPReport, []scanner.ScanError) {
		return scanner.GCPReport{Project: opts.GCPProject, FirewallRules: []scanner.FirewallFinding{{Name: "public", Network: "default", InsecureRules: []scanner.InsecureRule{{Protocol: "icmp", Port: "all", Source: "0.0.0.0/0"}}}}}, nil
	}}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-providers=gcp", "-gcp-project=project"}, &stdout, &stderr, clients); code != 0 || stderr.Len() != 0 {
		t.Fatalf("code %d stderr %q", code, &stderr)
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result["gcp"] == nil {
		t.Fatalf("unexpected providers: %v", result)
	}
}

func TestHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-help"}, &stdout, &stderr, scanners{}); code != 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("code %d stdout %q stderr %q", code, &stdout, &stderr)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("output unavailable") }

func TestOutputFailure(t *testing.T) {
	clients := scanners{gcp: func(context.Context, scanner.Options) (scanner.GCPReport, []scanner.ScanError) {
		return scanner.GCPReport{FirewallRules: []scanner.FirewallFinding{}}, nil
	}}
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"-providers=gcp", "-gcp-project=project"}, failingWriter{}, &stderr, clients); code != 1 || !strings.Contains(stderr.String(), "write JSON") {
		t.Fatalf("code %d stderr %q", code, &stderr)
	}
}
