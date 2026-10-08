# Cloud and container security review

## Executive summary

The original CloudFormation template creates an IAM user with an unrestricted administrator policy and a bucket without security hardening. Effective exposure rely on AWS account and/or organization controls, such as service control policies.

The Dockerfile contains two plaintext credentials, runs as root, makes the application world-writable, and starts from an operating system outside standard security maintenance. These are release-blocking findings. Any real values committed in the Dockerfile should be considered compromised and rotated; removing them from the latest commit is not sufficient.

The companion files [`cloudformation-secure.yaml`](./cloudformation-secure.yaml) and [`Dockerfile.secure`](./Dockerfile.secure) are improved examples. The CloudFormation example requires existing IAM roles and an access-log bucket. The Docker example requires application code that is not included in this directory.

> [!NOTE]
> I performed both manual and automated security reviews using kics, trivy, and snyk. Some decisions, such as using Red Hat UBI, reflect my personal preferences. The Docker health check assumes that the application exposes `/health` on port 8080.

The saved [Trivy results](scan-results/trivy/) report 9 misconfigurations in the original CloudFormation template and 5 in the original Dockerfile. The saved [KICS results](scan-results/kics/kics/) report 8 and 11 findings, respectively, including informational findings. These are findings against the original files. Both proposed solutions are scanned and iterated until no issues were left.

## CloudFormation review

### Findings

1. **Unrestricted admin permissions (critical).** `Action: "*"` together with `Resource: "*"` grants unrestricted permissions, subject to other applicable controls. This can enable access to sensitive information and privilege escalation.


2. **A persistent IAM user is the wrong identity primitive (high).** It encourages a console password or long-lived access keys, has no MFA requirement here, and has no short session lifetime. AWS recommends federation/Identity Center with temporary credentials for humans and IAM roles with temporary credentials for workloads. A user resource alone does not create credentials, but the design makes their later creation likely.

3. **The broad policy is inline and has no guardrail in the template (high).** It is coupled to one user, harder to inventory and reuse than a reviewed managed policy, has no permissions boundary, conditions, or explicit policy version, and does not restrict privilege escalation. Hard-coding `UserName` also creates a persistent account-scoped identity and requires named-IAM deployment capability.

4. **The S3 security intent is not explicit (medium).** S3 defaults are safer nowadays, but relying on defaults is not acceptable for a secure environment. The template does not explicitly require all four Block Public Access settings or encryption. Explicit properties are also important because CloudFormation drift detection only compares properties declared in the template.

5. **Transport and data-resilience controls are absent (medium).** There is no bucket policy denying non-TLS requests, no versioning, no retention safeguard and no protection against accidental deletion. Logging and monitoring are also outside the template. Depending on the data classification and sensitivity, customer-managed KMS keys, S3 Object Lock, replication, and centralized CloudTrail S3 data events should be used.

6. **Governance metadata is absent (low).** There is no description, tagging strategy, or ownership/data-classification metadata. These omissions make inventory, cost allocation, automated policy, and incident response harder.

### Hardened design

The improved template makes these changes:

- It removes the IAM user and its administrator policy. It does not create replacement IAM roles or identity policies: `KeyAdministratorArn` and `DataAccessRoleArn` must identify existing roles.
- It creates a customer-managed KMS key with automatic rotation. The key policy separates administration, data-key use, and grants restricted to AWS resources.
- The data bucket explicitly enables all Block Public Access controls, default SSE-KMS encryption with an S3 Bucket Key, bucket-owner-enforced ownership, versioning, incomplete multipart-upload cleanup, retention on deletion/replacement, and a deny policy for non-TLS transport. The KMS key is also retained on deletion/replacement.
- Server access logs are sent to the existing bucket named by `AccessLogBucketName`.
- It creates an account-scoped IAM Access Analyzer to detect resource access outside the account trust boundary.
- The data bucket and KMS key use generated physical names. The analyzer name is derived from the stack name. All three resources are tagged.

The existing data-access role still needs a separately managed least-privilege S3 policy. KMS permissions do not grant bucket or object access. Role trust, session duration, and permissions boundaries are assumed and should be managed outside this template.

The log destination must be in the **same AWS account and Region** as the data bucket, use SSE-S3 default encryption, and permit `logging.s3.amazonaws.com`. Provisioning it separately is a design choice, it could be defined in the template but again that bucket would need another bucket for access logs. For centralized collection across accounts, a separate CloudTrail design should be used. See [S3 server access logging requirements](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html).

Supply `Environment`, `AccessLogBucketName`, `KeyAdministratorArn`, and `DataAccessRoleArn`; `Environment` defaults to `production`. The deployment principal should only be allowed to pass an approved CloudFormation execution role, constrained with `cloudformation:RoleARN`; review a change set before execution. Ensure that the key policy lets the principal creating the key subsequently call `kms:PutKeyPolicy`, as required by [CloudFormation's KMS key-policy safety check](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kms-key.html). The hardened template contains no IAM user, role, or policy resources that require a `CAPABILITY_IAM`.

Relevant AWS guidance:

- [S3 Complaint bucket example](https://github.com/aws-cloudformation/aws-cloudformation-templates/blob/a0f43bc6d20813052892546f445037cf84c75b54/S3/compliant-bucket.yaml)
- [CloudFormation best practices](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html), including least privilege, change sets, drift detection, and Guard
- [IAM security best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [S3 security best practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html) and [Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [AWS Security Reference Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/) and its [AWS-maintained implementation examples](https://github.com/aws-samples/aws-security-reference-architecture-examples). These are reference patterns, not drop-in production templates.
- [IAM Access Analyzer policy generation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html)
- [CloudFormation drift detection](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-drift.html).

## Finding and remediating an existing user

> [!NOTE]
> Nowadays I am using Claude Code or GitHub Copilot to investigate incidents reported by Wiz or SOC. I have a custom skill defined and I preconfigure read-only roles for the accounts and pass them in a profile or via env vars. I have found great success with this approach and it would follow a similar approach in this case.


I would treat discovery, containment, investigation, and durable remediation as separate phases. Removing an admin policy immediately without understanding its consumers can cause an outage; leaving it active while investigating can worsen an incident.

1. **Establish scope**: inspect the user, inline and attached policies, group memberships, permissions, access keys and their last-used dates, console login profile, MFA devices, tags, and service-last-accessed data. Enumerate all IAM users organization-wide with AWS Config aggregators or equivalent inventory. Validate policy documents with IAM Access Analyzer. Security Hub/AWS Config managed controls should supplement this process, but the exact control coverage must be tested—some controls evaluate customer-managed policies and can miss an inline-policy variant.

2. **Look for exposure and use**: Search CloudTrail by the user's ARN/access-key ID and review source IPs, user agents, affected resources, IAM/STS activity, logging changes, and data access. Event History is limited; query the organization trail/CloudTrail Lake and relevant S3 data events for the full retention period. Correlate GuardDuty, Security Hub, IAM Access Analyzer, S3 Access Analyzer/Macie, and Wiz findings. Wiz is especially useful for graphing the identity's path to internet-exposed resources and sensitive data and for prioritizing toxic combinations.

3. **Contain suspicious access**: If use is unexpected, follow the incident process: preserve evidence, disable (then rotate/delete) access keys, remove the login profile, revoke or deny active sessions, and temporarily quarantine the principal with an explicit deny. Investigate actions already taken and rotate every credential the identity could read. Do this from a well-known break the glass or security role so the existing user cannot undo containment.

4. **Replace, test, and retire.** Determine whether the identity represents a person or workload. Move a person to federation/IAM Identity Center with MFA; move a workload to an IAM role (including OIDC federation for CI). IAM Access Analyzer can generate a starting policy from up to 90 days of CloudTrail management activity, but it omits some operations such as `iam:PassRole` and S3 data-event action detail, so review and test it. Scope actions, resources, and conditions manually. Test the replacement, disable the old path, monitor, and then delete the inline policy and user.

5. **Fix the source of truth.** Update the CloudFormation source, create and review a change set, deploy it, and run drift detection. An emergency console fix is acceptable for containment, but it must be reconciled into IaC immediately or the next deployment may recreate the vulnerability.

Starting example commands (read-only) are:

```bash
aws iam get-user --user-name UnrestrictedUser
aws iam list-user-policies --user-name UnrestrictedUser
aws iam get-user-policy --user-name UnrestrictedUser --policy-name FullAccess
aws iam list-attached-user-policies --user-name UnrestrictedUser
aws iam list-groups-for-user --user-name UnrestrictedUser
aws iam list-access-keys --user-name UnrestrictedUser
aws iam list-mfa-devices --user-name UnrestrictedUser
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=UnrestrictedUser
```


## Dockerfile review

### Findings and fixes

| Finding | Risk | Remediation |
|---|---|---|
| `ubuntu:18.04` | Ubuntu 18.04 left standard security maintenance in May 2023. A mutable tag is also not reproducible. | Use a small, supported, organization-approved runtime image; pin it to a reviewed digest in release builds and automate digest/security updates. The example uses `registry.access.redhat.com/ubi10/python-312-minimal`, pinned by tag and digest. |
| `USER root` | A process compromise starts with UID 0 inside the container and increases impact when runtime isolation is weak. | Create a fixed unprivileged UID/GID, own only required paths, switch with `USER`, and enforce non-root/read-only root filesystem/dropped capabilities in the orchestrator. |
| Plaintext `DB_PASSWORD` and `API_KEY` in `ENV` | Values are committed to source and persist in image configuration/layers and registries. | Rotate them. Inject runtime secrets from AWS Secrets Manager/SSM through the platform's secret integration. If a secret is required only during build, use a BuildKit secret mount not `ARG` or `ENV`. |
| `COPY . /app` | The entire build context may include `.git`, credentials, IaC, test data, and other unnecessary files. It also impacts image size. | Copy only the lock/dependency files and runtime application files; maintain a deny-by-default `.dockerignore`; never place secrets in the build context. |
| `chmod -R 777 /app` | Any process or user can replace application code, enabling tampering and persistence. | Use `COPY --chown`, fixed ownership, and modes such as directories `0755` and files `0644`; make the runtime filesystem read-only where possible. |
| Unnecessary `curl`, `vim`, and `dnsutils` | Increases image size, CVE count, and post-exploitation tooling. `python3-pip` is likely unnecessary during runtime. | Use a Python runtime image and multi-stage builds and install only pinned production dependencies. Keep diagnostics in an ephemeral debug container. |
| APT usage retains metadata and recommends | Produces a larger attack surface and less deterministic results. | If APT is required, combine update/install, add `--no-install-recommends`, pin where appropriate, and remove `/var/lib/apt/lists/*` in the same layer. |
| Shell-form `CMD python3 app.py` | Adds a shell process and can impair signal forwarding and clean shutdown. | Use exec form: `CMD ["python3", "app.py"]`. |
| Port 80 | A non-root process cannot bind a privileged port. `EXPOSE` does not publish or secure it. | Have the app listen on any port higher than 1024 and load-balance externally; apply network policy and do not expose the container directly. |
| No dependency lock/SBOM/health signal | Builds can drift and vulnerable components are harder to trace. | Pin/hash dependencies, generate an SBOM and provenance, sign the image, and add a meaningful orchestrator health probes (or a justified `HEALTHCHECK`). |

Docker's own guidance covers [build best practices](https://docs.docker.com/build/building/best-practices/) and explains why [`ARG`/`ENV` are inappropriate for build secrets](https://docs.docker.com/build/building/secrets/). Canonical documents the [Ubuntu 18.04 support dates](https://ubuntu.com/about/release-cycle?product=ubuntu&release=ubuntu&version=18.04+LTS).

`Dockerfile.secure` copies only `app.py`, creates UID/GID 10001, uses an exec-form command, and declares port 8080. The application must actually listen on that port and serve `/health`. No `app.py` or dependency lockfile was provided, The image waas not built and not scanned with tools such trivy, so the final image might contain known vulnerabilites.

## Preventing recurrence in CI/CD and AWS

Security controls should exist at several points so bypassing one does not permit a production (or lower environment) deployment:

1. **Developer/PR checks.** Protect the main branch, require review by code owners for IaC/pipeline changes, and prohibit direct production deploys. Run secret scanning before build. Use `aws cloudformation validate-template` and `cfn-lint` for template checks, plus CloudFormation Guard policies that reject wildcard IAM allows, IAM users, missing S3 encryption/public-access blocks/TLS enforcement, and unsafe deletions. AWS documents [`validate-template`](https://docs.aws.amazon.com/cli/latest/reference/cloudformation/validate-template.html) and [Guard CI usage and exit codes](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cloudformation-guard.html).

2. **Use the tools already available.** Run [Mend IaC scanning](https://docs.mend.io/platform/latest/scan-iac-with-mend-cli) (`mend iac 02-cloud-security-check`) on the source tree. After building an immutable image, run [Mend Container](https://docs.mend.io/platform/latest/configure-the-mend-cli-for-container-images) (`mend image <image:commit-sha>`); its secret detection is enabled by default. Enable Wiz Code repository/PR scanning for CloudFormation, Dockerfile, secrets, and dependencies, then scan the built image with the tenant's current Wiz CLI integration. Wiz documents the supported [code, IaC, image, and CI/CD workflow](https://www.wiz.io/lp/wiz-cli). Keep both tools' policies centrally managed: fail on secrets and critical/high exploitable issues, define severity/SLA thresholds, and require an owner, justification, compensating control, and expiry for exceptions. Do not silently duplicate every check—assign ownership and use Wiz's code-to-cloud/runtime context and Mend's SCA/license/container strengths.

3. **Artifact gate.** Build with `--pull` from an approved/internal registry, using a digest-pinned base; install locked dependencies; generate an SBOM and provenance; sign the image; and push only after policy passes. Scan the pushed digest again and deploy by digest, never by `latest`. Production admission should accept only trusted signatures and approved registries and enforce non-root, read-only filesystem, dropped Linux capabilities, resource limits, and a default-deny network policy.

4. **Deployment gate.** CI should federate to AWS with OIDC and short-lived credentials. Separate the pipeline role from a least-privilege CloudFormation execution role, constrain `iam:PassRole`/`cloudformation:RoleARN`, create a change control, get it reviewed, and require approval for production. Use CloudFormation Hooks/Control Tower proactive controls as a server-side backstop, plus SCPs and permissions boundaries to prevent creation of administrator identities and organization/account-level S3 Block Public Access to prevent public buckets even if CI is bypassed.

5. **Continuous detection.** Aggregate AWS Config, Security Hub CSPM, CloudTrail, GuardDuty, IAM Access Analyzer, Inspector/ECR, and Macie findings in the security account. Connect Wiz to the AWS organization and registries to detect runtime drift, exposed identities/data, and vulnerable deployed images; connect Mend to repositories/registries for continuous component monitoring. Alert on CloudFormation drift and out-of-band changes, route findings to accountable owners with remediation SLAs, and regularly exercise the break-glass and credential-compromise procedures.

This is defense in depth: scanner findings stop unsafe code at the pull request, artifact policy stops unsafe images, AWS-native controls prevent unsafe provisioning, and Wiz/AWS detective controls catch drift or bypasses in the live environment.
