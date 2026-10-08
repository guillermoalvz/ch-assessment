# Project budget alerts

This is an independent Terraform root so alerts can be deployed before the
billable infrastructure and kept after its teardown. Its state uses the shared
private GCS bucket under `01-gcp-terraform/budget-alerts`.

| Alert | Trigger |
| --- | --- |
| Actual 1 currency unit | 20% of the 5-unit calendar-month budget |
| Actual 5 currency units | 100% of that budget |
| Forecast 1 / 5 currency units | Estimated end-of-month spend exceeds those amounts |
| Relative monthly increase | Actual or forecast spend exceeds 150% of the previous month's cost by default |

Terraform reads the billing account's currency automatically. With
`monthly_budget_amount = 5` (the default), a EUR account gets **EUR 1 and EUR 5**
actual/forecast alerts; a USD account gets USD 1 and USD 5. Check
`terraform output alert_amounts` after deployment. No currency conversion is
performed. A custom `monthly_budget_amount` sets the upper threshold in the
account's currency, with the lower threshold at 20% of that amount.

The absolute budgets reset monthly and include every service in this project,
including the state bucket. They apply Free Tier credits but exclude promotional
trial credits. This monitors ongoing service cost even while trial credit pays
the bill. GCP rejects a budget whose currency differs from the account's
currency; reading it automatically avoids the previous hardcoded-USD failure.
See [the BudgetAmount currency requirement](https://docs.cloud.google.com/billing/docs/reference/budget/rest/v1/billingAccounts.budgets).

The relative alert remains useful after the upper threshold has already been
crossed. Set `monthly_spike_multiplier` to change its sensitivity; `1.5` means a
50% increase over the previous calendar month. A new project has no reliable
prior-month baseline, so the fixed and forecast alerts provide initial coverage.
Forecasting can also need sufficient usage history. A partial first month can
produce a small baseline and trigger expected growth alerts the following month.

This is monthly trend detection. It does not detect a USD 1 jump within an hour,
and billing data and emails can be delayed by hours. For anomaly detection,
Google also provides Billing → Anomalies → Manage anomalies, where a billing
administrator can configure cost-impact/deviation thresholds and individual
notifications. That separate account-wide control is not managed by these
Terraform resources. See [GCP budget behavior](https://docs.cloud.google.com/billing/docs/how-to/budgets)
and [native cost anomalies](https://docs.cloud.google.com/billing/docs/how-to/manage-anomalies).

## Deployment

Terraform and `gcloud` must be preinstalled. First
[bootstrap the state bucket](../state-bootstrap/README.md). The provisioning
identity needs `roles/billing.costsManager` on the billing account, API enablement
permissions on the project, `serviceusage.services.use` for its quota project,
`billing.accounts.get` to read the account currency,
`resourcemanager.projects.get` to resolve the project number, and object access
on the state bucket. If adding custom emails, it additionally needs
`roles/monitoring.notificationChannelEditor` on the project. The Terraform code
does not grant these administrative permissions to the VM or SSH users.

```bash
cd 01-gcp-terraform/budget-alerts
cp terraform.tfvars.example terraform.tfvars
cp backend.hcl.example backend.hcl
# Set project_id and the linked billing_account_id.
# Leave monthly_budget_amount = 5 for EUR 1 / EUR 5 on a EUR account.
# Set optional notification_emails and the existing backend bucket.
gcloud auth application-default set-quota-project YOUR_PROJECT_ID
terraform init -backend-config=backend.hcl
terraform plan -out=budgets.tfplan
terraform apply budgets.tfplan
```

If a previous apply failed with `Error 400: Request contains an invalid argument`
on `google_billing_budget.monthly`, regenerate the plan with this version before
applying. Old saved plans retain the hardcoded USD currency. If Terraform already
created the relative budget, notification channels or APIs during that failed
apply, its remote state retains them; do not delete state or start over.

By default, billing account admins and billing account users receive email
alerts. Optional `notification_emails` adds up to five email channels without
disabling those defaults. Check the channels and complete any verification
requested by Cloud Monitoring. Creating the configuration does not itself send
a test email; delivery is triggered by reported cost crossing the configured
threshold. To verify, inspect the two budgets under Billing → Budgets & alerts
and check project scope, thresholds, savings and recipients. Do not generate
expensive usage merely to test an alert.

```bash
# In a fresh checkout or with an unused local Terraform data directory:
# Mocked tests need no billing account access and send no email.
# Initialization may download the provider.
terraform init -backend=false
terraform validate
terraform test
```

