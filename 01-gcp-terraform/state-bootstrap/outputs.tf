output "bucket_name" {
  description = "Bucket shared by the three GCS backends."
  value       = google_storage_bucket.state.name
}

output "state_prefixes" {
  description = "Separate state namespaces; each supports Terraform locking."
  value = {
    infrastructure = "01-gcp-terraform/secure-web"
    budgets        = "01-gcp-terraform/budget-alerts"
    bootstrap      = "01-gcp-terraform/state-bootstrap"
  }
}
