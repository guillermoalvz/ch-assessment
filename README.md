# CH Technical Assessment

This repository contains the four requested scenarios.

> [!IMPORTANT]  
> I wrote the original version of this README myself. Each scenario includes a disclosure detailing how I used OpenAI Codex to complete the tasks.

## Scenario 1: Secure GCP Infrastructure with Terraform

### AI Usage Disclosure

OpenAI Codex was used to implement the Terraform module. The technical decisions in the following section were mine and were not suggested by Codex. I manually reviewed every line of code, tested the stack and deployed it to an empty GCP project.

### Technical decisions

- Using IAP for SSH instead of allowlisting my public IP address. This approach keeps the setup simple and restricts SSH to IAP's trusted proxy IP range. Personally, I would use a ZTNA solution such as Tailscale.
- Enabling MFA for SSH. I have configured this before and it was straightforward to set up.
- Keeping the Terraform module in the same repository. In a real scenario, I would use a separate module repository and reference a pinned version, as shown in the comment at [main.tf](01-gcp-terraform/main.tf#L2).
- Bootstrapped a GCS bucket to store the Terraform states.
- Since everything is deployed in a personal GCP Project, billing budgets and alerts are also managed via Terraform.
- I decided **NOT** to create an empty "public subnet," although it was included in the scenario, because the global external Application Load Balancer has no use for it.

### Detailed documentation

> [!NOTE]  
> AI was used to generate the detailed documentation linked below. I manually reviewed it and made edits where applicable.

See [Secure GCP Infrastructure with Terraform](01-gcp-terraform/README.md).

## Scenario 2: Cloud Security Check

### AI Usage Disclosure

OpenAI Codex, specifically the Daybreak Blue model, was used to perform a security review. For the [cloudformation-secure.yaml](02-cloud-security-check/cloudformation-secure.yaml) template, I used GPT-6.1 Sol to help fix the issues I identified and those reported by Trivy and KICS. I created [Dockerfile.secure](02-cloud-security-check/Dockerfile.secure) entirely myself.

### Technical decisions

- Using KICS, Trivy and Snyk to scan the Dockerfile and the CloudFormation template. For transparency, I have included the Trivy and KICS outputs. I excluded the Snyk output because it did not provide additional useful findings.
- Dockerfile:
  - Using a minimal Red Hat UBI Python image and pinned it by digest.
  - Removed the hardcoded credentials. Depending on the requirements, I would inject secrets at runtime as environment variables or mounted volumes, leveraging a secret store such as HashiCorp Vault/Azure Key Vault/AWS Systems Manager Parameter Store/AWS Secrets Manager/GCP Secret Manager.
- CloudFormation:
  - Used KICS and Trivy to guide remediation and iterated until the scans came clean. The improved template assumes there is an existing bucket for access logs (chicken-and-egg problem).
  - Added a customer managed KMS key for server-side encryption, with separate key-policy statements for key administration, data access and grants for AWS resources.

### Detailed documentation

> [!NOTE]  
> AI was used to generate the detailed documentation linked below. I manually reviewed it and made edits where applicable.

See [Cloud Security Check](02-cloud-security-check/README.md).

## Scenario 3: Automate Security Checks with Go

### AI Usage Disclosure

OpenAI Codex was used to create the Golang tool. I reviewed the complete implementation and tested it against a personal GCP test project, AWS account and Azure subscription. The outputs are provided in the [findings](03-public-traffic-tool/findings) folder, although the GCP project ID, Azure subscription ID and AWS security group IDs were manually redacted.

### Technical decisions

- The JSON output includes the attributes in the provided example and adds fields I deemed valuable for each cloud provider. For AWS, it includes the scanned regions and each security group's region. For GCP, `name` is the firewall rule name and `network` is the network resource URL. For Azure, it includes the subscription ID and rule details such as `source_prefix`, `source_ports`, `destinations` and `priority` where applicable.

### Detailed documentation

> [!NOTE]  
> AI was used to generate the detailed documentation linked below. I manually reviewed it and made edits where applicable.

See [Automate Security Checks with Go](03-public-traffic-tool/README.md).

## Scenario 4: Third-Party Dependency Security Audit

### AI Usage Disclosure

OpenAI Codex was used to create the Python scripts for auditing dependencies and generating markdown reports.

### Technical decisions

- The audit script supports `snyk test`, `npm audit` and `yarn audit` (v1/Classic).
- It generates raw scanner output and normalized JSON and CSV exports that aggregate repeated paths per scanner, package and advisory.
- I have decided to use both yarn and npm, because although they provide the same amount of vulnerabilities. `npm` is installed by default in most installations, but the audit ouput does not contain CVEs and `yarn audit` output includes them.

### Detailed documentation

> [!NOTE]  
> AI was used to generate the detailed documentation linked below. I manually reviewed it and made edits where applicable.

See [Third-Party Dependency Security Audit](04-dependency-audit/README.md).
