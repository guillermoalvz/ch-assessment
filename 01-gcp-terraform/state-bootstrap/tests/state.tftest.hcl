mock_provider "google" {}

variables {
  project_id       = "test-project"
  bucket_name      = "test-project-tfstate"
  state_principals = ["user:engineer@example.com"]
}

run "protected_remote_state_storage" {
  command = apply

  assert {
    condition = (
      google_storage_bucket.state.location == "US-CENTRAL1" &&
      google_storage_bucket.state.storage_class == "STANDARD" &&
      google_storage_bucket.state.uniform_bucket_level_access &&
      google_storage_bucket.state.public_access_prevention == "enforced" &&
      google_storage_bucket.state.versioning[0].enabled &&
      google_storage_bucket.state.soft_delete_policy[0].retention_duration_seconds == 604800 &&
      !google_storage_bucket.state.force_destroy
    )
    error_message = "State must be private, recoverable, and protected against forced bucket deletion."
  }

  assert {
    condition = (
      one(one(google_storage_bucket.state.lifecycle_rule).condition).with_state == "ARCHIVED" &&
      one(one(google_storage_bucket.state.lifecycle_rule).condition).num_newer_versions == 10 &&
      one(one(google_storage_bucket.state.lifecycle_rule).condition).days_since_noncurrent_time == 30
    )
    error_message = "Cleanup must affect only older archived generations and retain at least ten newer versions."
  }

  assert {
    condition = (
      google_storage_bucket_iam_member.state_access["user:engineer@example.com"].bucket == google_storage_bucket.state.name &&
      google_storage_bucket_iam_member.state_access["user:engineer@example.com"].role == "roles/storage.objectAdmin" &&
      length(toset(values(output.state_prefixes))) == 3
    )
    error_message = "State users must have object-only bucket permissions and stacks must have distinct prefixes."
  }
}

run "reject_public_state_access" {
  command = plan
  variables {
    state_principals = ["allUsers"]
  }
  expect_failures = [var.state_principals]
}

run "reject_empty_state_access" {
  command = plan
  variables {
    state_principals = []
  }
  expect_failures = [var.state_principals]
}
