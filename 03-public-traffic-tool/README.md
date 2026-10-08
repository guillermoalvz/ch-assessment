# Public inbound firewall scanner

A Go CLI that uses the official AWS SDK v2, Google Compute Engine Go API client,
and Azure Go SDK to list inbound rules permitting public IPv4 traffic. The tool
only reads cloud configuration.

Every inbound allow from `0.0.0.0/0` is a finding, including a single TCP/UDP
port, a port range, ICMP, an arbitrary IP protocol, or all protocols and ports.
Only resources with findings appear in the JSON.

## Build and run

Requires Go 1.26 or newer. Dependency versions and checksums are pinned in
`go.mod` and `go.sum`. These files record the selected versions; they are the latest available versions as of 2026-10-08.

```bash
cd 03-public-traffic-tool
go build -o bin/public-traffic-tool ./cmd/public-traffic-tool

# All three providers (after configuring credentials below).
./bin/public-traffic-tool \
  -gcp-project=my-project \
  -azure-subscription=00000000-0000-0000-0000-000000000000 \
  > findings.json

# AWS only: scan selected regions instead of discovering enabled regions.
./bin/public-traffic-tool -providers=aws -aws-profile=audit \
  -aws-regions=us-east-1,eu-west-1 > findings.json

# GCP or Azure only.
./bin/public-traffic-tool -providers=gcp -gcp-project=my-project
./bin/public-traffic-tool -providers=azure -azure-subscription=00000000-0000-0000-0000-000000000000

./bin/public-traffic-tool -help
```

To run without building a binary, use `go run ./cmd/public-traffic-tool [flags]`.

## Project layout

```text
cmd/public-traffic-tool/main.go  Executable entry point and signal handling
internal/cli/                    Flags, scan orchestration, JSON output, CLI tests
internal/scanner/                Cloud clients, detection, report types, scanner tests
bin/                             Local build output (ignored by Git)
go.mod, go.sum                   Module and dependency definitions
```

Tests live alongside the package they exercise. Run `go test ./...` from this
directory to test both internal packages.

Defaults: all three providers, all enabled AWS regions in the current AWS
partition, and a ten-minute total deadline. `-aws-region` sets the region used
for discovery; otherwise the SDK's configured region is used, falling back to
`us-east-1`. When `-aws-regions` is provided, region discovery is skipped;
if neither the flag nor SDK configuration sets a region, the first supplied
region is used to initialize the SDK.
`-timeout=20m` changes the total deadline. SIGINT/SIGTERM cancel requests.

The AWS credential identity determines the account being scanned. GCP scans
all VPC firewall rules in one specified project, across all its networks. Azure
scans all NSGs in one specified subscription, across all resource groups and
regions. Run separately for additional accounts, projects, subscriptions, or
AWS partitions; the tool does not discover an entire organization.

## Authentication and read permissions

Use the SDK credential chains; no credentials are embedded in the tool or
passed through CLI flags.

| Cloud | Authentication | Minimum list permissions |
| --- | --- | --- |
| AWS | Default SDK chain: environment credentials, shared config/profiles, SSO, web identity, or workload roles. `-aws-profile` selects a profile. | `ec2:DescribeSecurityGroups`; also `ec2:DescribeRegions` for default region discovery (these actions require `Resource: "*"`). |
| GCP | Application Default Credentials (ADC), such as local ADC, workload identity, or `GOOGLE_APPLICATION_CREDENTIALS` pointing to a credential file. | `compute.firewalls.list` on the project; enable the Compute Engine API. The client requests the read-only Compute OAuth scope. |
| Azure | `DefaultAzureCredential`, such as environment credentials, workload/managed identity, or an Azure CLI login. | `Microsoft.Network/networkSecurityGroups/read` on the subscription, e.g. subscription-level Reader. |

For local development, configure the relevant providers:

```bash
aws configure sso --profile audit
aws sso login --profile audit

gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=my-project

az login
export AZURE_SUBSCRIPTION_ID=00000000-0000-0000-0000-000000000000
```

`GOOGLE_CLOUD_PROJECT` and `AZURE_SUBSCRIPTION_ID` supply scope defaults;
the corresponding flags override them. Scope settings do not authenticate you.
For unattended Azure environment authentication, configure `AZURE_TENANT_ID`,
`AZURE_CLIENT_ID`, and an appropriate credential such as `AZURE_CLIENT_SECRET`
outside the repository.

SDK references: [AWS default credentials](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-gosdk.html),
[Google ADC](https://cloud.google.com/docs/authentication/provide-credentials-adc),
and [Azure DefaultAzureCredential](https://learn.microsoft.com/en-us/azure/developer/go/sdk/authentication/credential-chains).

## Detection details and scope

- **AWS:** Inspects `IpPermissions` (ingress), not egress. Handles `-1` (all
  protocols), numeric TCP/UDP/ICMP identifiers, single ports, and ranges.
  For ICMP, `icmp_type`/`icmp_code` retain the actual restrictions; `-1` means
  any type/code. `port: "all"` for ICMP means there is no transport port.
- **GCP:** Inspects enabled ingress rules' `allowed` entries. Empty direction
  defaults to ingress. An omitted source defaults to public IPv4 only when
  neither source tags nor source service accounts are specified. An explicit
  public source range is still a finding when source tags/accounts are present:
  GCP combines these source selectors with OR. Missing allowed ports mean all
  ports. Deny-only and disabled rules are excluded.
- **Azure:** Inspects custom and default NSG rules with `Inbound` and `Allow`.
  Handles single/augmented source prefixes and destination port ranges. Public
  sources include `0.0.0.0/0`, `*` (the portal's Any), `Any`, and the `Internet`
  service tag. The reported `source` is normalized to `0.0.0.0/0`; `source_prefix`
  preserves wildcard/tag spelling. The Internet tag represents public Internet
  addresses rather than literally every IPv4 address. Rule name, priority,
  source port restrictions, and destination addresses are retained.

IPv6 `::/0`, combined narrower CIDRs,
AWS network ACLs/Network Firewall, GCP hierarchical/network firewall policies,
and Azure Firewall were left outside this exercise's scope.

API references: [AWS security groups](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html),
[GCP firewall source semantics](https://cloud.google.com/compute/docs/reference/rest/v1/firewalls),
and [Azure NSG rules](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview).

## JSON output and exit status

Stdout contains one valid, indented JSON document for a scan. Diagnostics and
help go to stderr. Unselected provider keys are omitted. Selected providers
with no findings have empty arrays, never `null`. `port` is consistently a
string: `"8080"`, `"1000-2000"`, or `"all"`. Multiple port specifications produce
separate entries. Resources and rules are sorted for readable reports.

Example (illustrative):

```json
{
  "aws": {
    "regions": ["us-east-1"],
    "security_groups": [
      {
        "id": "sg-12345678",
        "name": "open-sg",
        "region": "us-east-1",
        "insecure_rules": [
          {"protocol": "tcp", "port": "8080", "source": "0.0.0.0/0"}
        ]
      }
    ]
  },
  "gcp": {
    "project": "my-project",
    "firewall_rules": [
      {
        "name": "allow-icmp",
        "network": "https://www.googleapis.com/compute/v1/projects/my-project/global/networks/default",
        "insecure_rules": [
          {"protocol": "icmp", "port": "all", "source": "0.0.0.0/0"}
        ]
      }
    ]
  },
  "azure": {
    "subscription": "00000000-0000-0000-0000-000000000000",
    "nsgs": [
      {
        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.Network/networkSecurityGroups/open-nsg",
        "name": "open-nsg",
        "insecure_rules": [
          {"name": "allow-all", "protocol": "all", "port": "all", "source": "0.0.0.0/0", "source_prefix": "*", "priority": 100}
        ]
      }
    ]
  }
}
```

- `0`: scan completed (including when insecure rules were found), or help.
- `1`: scan incomplete due to authentication/API errors, timeout/cancellation,
  or an output failure.
- `2`: invalid CLI arguments or missing required scope settings; no JSON scan
  document is emitted.

API errors are recorded in a top-level `errors` array with `provider`, `scope`
(when known), and `message`. Successfully fetched pages and other providers'
findings are retained. AWS continues to other regions after a regional failure.
The AWS `regions` array identifies requested/discovered scope, not successful
completion; inspect `errors` and the exit status before treating results as
complete. Empty findings accompanied by errors do not establish a clean scan.

## Validation

```bash
go test ./...
go vet ./...
```

Tests cover public/private sources, inbound/outbound and allow/deny distinctions,
ports/ranges, ICMP, implicit GCP sources, Azure augmented rules, all three SDKs'
pagination, retention of findings when later pages fail, and CLI JSON/exit
behavior. Tests use synthetic rules, mocked AWS responses, and local HTTP/TLS
servers; they require no cloud credentials and do not contact cloud services.
