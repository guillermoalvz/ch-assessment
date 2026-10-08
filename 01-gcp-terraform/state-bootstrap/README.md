# Terraform state in GCS

All three deployable Terraform roots use the same private GCS bucket with
distinct prefixes. GCS supports Terraform state locking; bucket versioning and
seven-day soft deletion provide recovery. The bucket uses uniform IAM access,
public access prevention and Google's default encryption at rest. It is protected
by `prevent_destroy` and `force_destroy = false`.

| Root | Prefix (default workspace state is `default.tfstate`) |
| --- | --- |
| Infrastructure (`../`) | `01-gcp-terraform/secure-web` |
| Budgets (`../budget-alerts/`) | `01-gcp-terraform/budget-alerts` |
| Bucket configuration (`./`) | `01-gcp-terraform/state-bootstrap` |

The infrastructure module grants no state access to the workload VM or SSH users. Explicit
`state_principals` get `roles/storage.objectAdmin` **on this bucket only**, which
allows backend reads, writes, and lock deletion. Separate prefixes prevent state
collisions; they do not isolate permissions between these trusted operators.
Archived generations are deleted only after 30 days and when at least ten newer
versions exist. Live state and recent recovery history are retained. There is no
locked retention policy, which would prevent Terraform deleting its lock object.

## Bootstrap without local Terraform state

A GCS backend requires its bucket to exist before Terraform starts. To avoid a
bootstrap state left on disk, create the bucket once with Google Cloud CLI, then
import its configuration directly into its own GCS backend.

Terraform and `gcloud` must be preinstalled. Run with a provisioning identity,
using ADC. Initial creation needs bucket-create
permissions (for example, temporary project-level `roles/storage.admin`). After
bootstrap, bucket administration can be scoped to this one bucket. Ordinary
Terraform infrastructure/budget operators need only the object role here, plus
their respective provisioning permissions.

```bash
cd 01-gcp-terraform/state-bootstrap
gcloud auth login
gcloud auth application-default login

# Replace these placeholders. The bucket name must be globally unique.
export PROJECT_ID="your-gcp-project-id"
export STATE_BUCKET="your-project-id-tfstate"
bash bootstrap.sh "$PROJECT_ID" "$STATE_BUCKET"

cp terraform.tfvars.example terraform.tfvars
cp backend.hcl.example backend.hcl
# Edit terraform.tfvars: project_id, bucket_name, trusted state_principals.
# Edit backend.hcl: bucket = the same STATE_BUCKET.
terraform init -backend-config=backend.hcl
terraform import google_storage_bucket.state "$STATE_BUCKET"
terraform plan -out=bootstrap.tfplan
terraform apply bootstrap.tfplan
```

`bootstrap.sh` fails if bucket creation fails, including if that name already
exists. It never updates an unrelated existing bucket. If creation succeeds but
the versioning command fails, fix that failure and enable versioning before
initializing Terraform. An existing bucket you own can be reused after checking
its project, location (`us-central1`), public access prevention, uniform access
and versioning; skip creation and import it. Do not use a bucket holding unrelated
objects: the archived-version cleanup policy applies bucket-wide.

For a fresh infrastructure deployment, configure `../backend.hcl` with this same
bucket and initialize using `terraform init -backend-config=backend.hcl`. Configure
`../budget-alerts/backend.hcl` likewise. Deploy budget alerts before the VM/load
balancer. Each backend fixes its own prefix in version-controlled `backend.tf`.
Keep backend files free of credentials; Terraform uses ADC, or set
`GOOGLE_BACKEND_IMPERSONATE_SERVICE_ACCOUNT` for short-lived impersonation.

## Migrate an existing local state

The previous infrastructure configuration used local state. If you already
applied it, migrate from the same checkout and directory that holds that state.
Never recreate resources or use `-reconfigure` to bypass a migration.

```bash
cd 01-gcp-terraform
cp backend.hcl.example backend.hcl
# Set bucket to the bootstrapped state bucket.
# Keep a private backup outside the repo before migration.
terraform init -migrate-state -backend-config=backend.hcl
# Accept Terraform's prompt to copy the existing state into GCS.
terraform state list
terraform plan
gcloud storage ls "gs://$STATE_BUCKET/01-gcp-terraform/secure-web/"
```

Check the resource list and plan against the previous deployment. The plan
should not recreate infrastructure merely because state moved. For a checkout
initialized with the old backend but containing **no state**, use
`terraform init -reconfigure -backend-config=backend.hcl` instead. Preserve private
local backups until remote state is confirmed; they are gitignored. Do not migrate
onto a prefix already containing another deployment's state.

The Terraform backend cache remains in local `.terraform/`, and saved plans can
contain state and private values; both are gitignored. The authoritative deployed
state lives in GCS. Backend configuration cannot create a bucket by itself, so
these bootstrap/migration steps must actually be run in your account.

## Validation and lifecycle

Run these checks in a fresh checkout or with an unused local Terraform data directory:

```bash
terraform init -backend=false
terraform validate
terraform test
python3 -m unittest discover -s tests -p 'test_*.py'
```

Validation and tests do not create storage or require access to a live GCS backend;
the Terraform tests use mocked providers. Initialization may require network
access to download the provider. Retain the bucket and budgets when destroying demo
infrastructure. Delete this bucket only after explicitly retiring all dependent
states and keeping the necessary backups; the configuration prevents routine
`terraform destroy` from removing it.

See [HashiCorp's GCS backend and locking documentation](https://developer.hashicorp.com/terraform/language/backend/gcs).
