terraform {
  backend "gcs" {
    prefix = "01-gcp-terraform/budget-alerts"
  }
}
