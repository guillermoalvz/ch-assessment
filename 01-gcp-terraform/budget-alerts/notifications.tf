resource "google_monitoring_notification_channel" "email" {
  for_each     = var.notification_emails
  project      = var.project_id
  display_name = "Terraform budget email"
  type         = "email"
  enabled      = true

  labels = {
    email_address = each.value
  }

  depends_on = [google_project_service.required]
}
