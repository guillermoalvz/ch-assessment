provider "google" {
  project = var.project_id
  # Use ADC or short-lived impersonation; never a downloaded key.
}
