resource "google_project_service" "required" {
  for_each = toset([
    "billingbudgets.googleapis.com",
    "cloudbilling.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "monitoring.googleapis.com",
  ])
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

data "google_project" "target" {
  project_id = var.project_id
  depends_on = [google_project_service.required["cloudresourcemanager.googleapis.com"]]
}

# Budgets must use the account's currency; the API rejects a different one.
# Avoid listing associated projects, which would require extra permissions.
data "google_billing_account" "target" {
  billing_account = var.billing_account_id
  lookup_projects = false
  depends_on      = [google_project_service.required["cloudbilling.googleapis.com"]]
}
