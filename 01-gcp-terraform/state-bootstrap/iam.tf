# Backend locking requires object create/read/delete. This is a bucket-level
# grant; it permits no infrastructure changes or bucket administration.
resource "google_storage_bucket_iam_member" "state_access" {
  for_each = var.state_principals
  bucket   = google_storage_bucket.state.name
  role     = "roles/storage.objectAdmin"
  member   = each.value
}
