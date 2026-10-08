package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ch-assessment/public-traffic-tool/internal/scanner"
)

type options struct {
	scanner.Options
	providers []string
	timeout   time.Duration
}

type scanners struct {
	aws   func(context.Context, scanner.Options) (scanner.AWSReport, []scanner.ScanError)
	gcp   func(context.Context, scanner.Options) (scanner.GCPReport, []scanner.ScanError)
	azure func(context.Context, scanner.Options) (scanner.AzureReport, []scanner.ScanError)
}

func csv(value string) ([]string, error) {
	var values []string
	seen := make(map[string]bool)
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, errors.New("comma-separated lists must not contain empty entries")
		}
		if !seen[item] {
			seen[item] = true
			values = append(values, item)
		}
	}
	return values, nil
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	var opts options
	flags := flag.NewFlagSet("public-traffic-tool", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var providerList, regionList string
	flags.StringVar(&providerList, "providers", "aws,gcp,azure", "comma-separated providers: aws,gcp,azure")
	flags.StringVar(&opts.AWSRegion, "aws-region", "", "AWS region for discovery (otherwise use SDK configuration, then us-east-1)")
	flags.StringVar(&regionList, "aws-regions", "", "AWS regions to scan; default: discover all enabled regions in the current partition")
	flags.StringVar(&opts.AWSProfile, "aws-profile", "", "AWS shared configuration profile (otherwise use SDK defaults)")
	flags.StringVar(&opts.GCPProject, "gcp-project", os.Getenv("GOOGLE_CLOUD_PROJECT"), "GCP project ID (or GOOGLE_CLOUD_PROJECT)")
	flags.StringVar(&opts.AzureSubscription, "azure-subscription", os.Getenv("AZURE_SUBSCRIPTION_ID"), "Azure subscription ID (or AZURE_SUBSCRIPTION_ID)")
	flags.DurationVar(&opts.timeout, "timeout", 10*time.Minute, "total scan timeout")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: public-traffic-tool [flags]\nScan public IPv4 inbound firewall allows and emit JSON on stdout.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return opts, err
	}
	if flags.NArg() != 0 {
		return opts, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	var err error
	opts.providers, err = csv(providerList)
	if err != nil {
		return opts, fmt.Errorf("providers: %w", err)
	}
	opts.GCPProject = strings.TrimSpace(opts.GCPProject)
	opts.AzureSubscription = strings.TrimSpace(opts.AzureSubscription)
	for _, provider := range opts.providers {
		switch provider {
		case "aws":
		case "gcp":
			if opts.GCPProject == "" {
				return opts, errors.New("GCP requires -gcp-project or GOOGLE_CLOUD_PROJECT")
			}
		case "azure":
			if opts.AzureSubscription == "" {
				return opts, errors.New("Azure requires -azure-subscription or AZURE_SUBSCRIPTION_ID")
			}
		default:
			return opts, fmt.Errorf("unknown provider %q (use aws,gcp,azure)", provider)
		}
	}
	if regionList != "" {
		opts.AWSRegions, err = csv(regionList)
		if err != nil {
			return opts, fmt.Errorf("AWS regions: %w", err)
		}
	}
	if opts.timeout <= 0 {
		return opts, errors.New("timeout must be positive")
	}
	return opts, nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, clients scanners) int {
	opts, err := parseOptions(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()
	var report scanner.Report
	for _, provider := range opts.providers {
		switch provider {
		case "aws":
			result, scanErrors := clients.aws(ctx, opts.Options)
			report.AWS = &result
			report.Errors = append(report.Errors, scanErrors...)
		case "gcp":
			result, scanErrors := clients.gcp(ctx, opts.Options)
			report.GCP = &result
			report.Errors = append(report.Errors, scanErrors...)
		case "azure":
			result, scanErrors := clients.azure(ctx, opts.Options)
			report.Azure = &result
			report.Errors = append(report.Errors, scanErrors...)
		}
	}
	report.Sort()
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintf(stderr, "write JSON: %v\n", err)
		return 1
	}
	if len(report.Errors) > 0 {
		fmt.Fprintln(stderr, "scan incomplete; see JSON errors")
		return 1
	}
	return 0
}

// Run executes the CLI with the default cloud scanners and returns an exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return run(ctx, args, stdout, stderr, scanners{
		aws:   scanner.ScanAWS,
		gcp:   scanner.ScanGCP,
		azure: scanner.ScanAzure,
	})
}
