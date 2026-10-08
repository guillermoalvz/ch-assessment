package scanner

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func awsRules(group types.SecurityGroup) []InsecureRule {
	var findings []InsecureRule
	for _, permission := range group.IpPermissions {
		public := false
		for _, source := range permission.IpRanges {
			if aws.ToString(source.CidrIp) == publicIPv4 {
				public = true
				break
			}
		}
		if !public {
			continue
		}
		rule := InsecureRule{Protocol: aws.ToString(permission.IpProtocol), Port: "all", Source: publicIPv4}
		switch rule.Protocol {
		case "-1":
			rule.Protocol = "all"
		case "6":
			rule.Protocol = "tcp"
		case "17":
			rule.Protocol = "udp"
		case "1":
			rule.Protocol = "icmp"
		case "58":
			rule.Protocol = "icmpv6"
		}
		switch rule.Protocol {
		case "tcp", "udp":
			if permission.FromPort != nil && permission.ToPort != nil {
				rule.Port = strconv.FormatInt(int64(*permission.FromPort), 10)
				if *permission.FromPort != *permission.ToPort {
					rule.Port += "-" + strconv.FormatInt(int64(*permission.ToPort), 10)
				}
			}
		case "icmp", "icmpv6":
			rule.ICMPType = permission.FromPort
			rule.ICMPCode = permission.ToPort
		}
		findings = append(findings, rule)
	}
	return findings
}

// A narrow SDK interface lets pagination be checked without real credentials.
type securityGroupsAPI interface {
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

func collectAWS(ctx context.Context, client securityGroupsAPI, region string) ([]SecurityGroupFinding, error) {
	findings := make([]SecurityGroupFinding, 0)
	pager := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{}, func(opts *ec2.DescribeSecurityGroupsPaginatorOptions) {
		opts.StopOnDuplicateToken = true
	})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("list security groups: %w", err)
		}
		for _, group := range page.SecurityGroups {
			if rules := awsRules(group); len(rules) > 0 {
				findings = append(findings, SecurityGroupFinding{
					ID: aws.ToString(group.GroupId), Name: aws.ToString(group.GroupName), Region: region, InsecureRules: rules,
				})
			}
		}
	}
	return findings, nil
}

// ScanAWS lists public inbound allows in AWS security groups.
func ScanAWS(ctx context.Context, opts Options) (AWSReport, []ScanError) {
	result := AWSReport{Regions: make([]string, 0), SecurityGroups: make([]SecurityGroupFinding, 0)}
	loadOptions := []func(*config.LoadOptions) error{}
	if opts.AWSRegion != "" {
		loadOptions = append(loadOptions, config.WithRegion(opts.AWSRegion))
	}
	if opts.AWSProfile != "" {
		loadOptions = append(loadOptions, config.WithSharedConfigProfile(opts.AWSProfile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return result, []ScanError{{Provider: "aws", Message: fmt.Sprintf("load AWS configuration: %v", err)}}
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
		if len(opts.AWSRegions) > 0 {
			cfg.Region = opts.AWSRegions[0]
		}
	}
	result.Regions = append(result.Regions, opts.AWSRegions...)
	if len(result.Regions) == 0 {
		regions, err := ec2.NewFromConfig(cfg).DescribeRegions(ctx, &ec2.DescribeRegionsInput{AllRegions: aws.Bool(false)})
		if err != nil {
			return result, []ScanError{{Provider: "aws", Scope: cfg.Region, Message: fmt.Sprintf("discover enabled regions: %v", err)}}
		}
		for _, region := range regions.Regions {
			if name := aws.ToString(region.RegionName); name != "" {
				result.Regions = append(result.Regions, name)
			}
		}
		if len(result.Regions) == 0 {
			return result, []ScanError{{Provider: "aws", Message: "region discovery returned no enabled regions"}}
		}
	}
	sort.Strings(result.Regions)
	var scanErrors []ScanError
	for _, region := range result.Regions {
		if err := ctx.Err(); err != nil {
			scanErrors = append(scanErrors, ScanError{Provider: "aws", Scope: region, Message: fmt.Sprintf("remaining regions not scanned: %v", err)})
			break
		}
		regionalConfig := cfg
		regionalConfig.Region = region
		findings, err := collectAWS(ctx, ec2.NewFromConfig(regionalConfig), region)
		result.SecurityGroups = append(result.SecurityGroups, findings...)
		if err != nil {
			scanErrors = append(scanErrors, ScanError{Provider: "aws", Scope: region, Message: err.Error()})
		}
	}
	return result, scanErrors
}
