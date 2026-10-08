# Bucket is created once with gcloud before Terraform initializes its backend,
# then imported directly into remote state (see README), avoiding local state.
resource "google_storage_bucket" "state" {
  project                     = var.project_id
  name                        = var.bucket_name
  location                    = "US-CENTRAL1"
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  labels                      = { purpose = "terraform-state", managed_by = "terraform" }

  versioning {
    enabled = true
  }

  soft_delete_policy {
    retention_duration_seconds = 604800 # Seven days.
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      with_state                 = "ARCHIVED"
      days_since_noncurrent_time = 30
      num_newer_versions         = 10
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}
