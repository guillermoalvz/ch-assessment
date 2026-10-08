provider "google" {
  project               = var.project_id
  billing_project       = var.project_id
  user_project_override = true
  # Billing Budgets requires an explicit quota project for user ADC.
}
