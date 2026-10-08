# Dedicated identity, no keys, no project roles and no OAuth scopes. This demo
# workload needs no Google API privileges. Never attach the default compute SA.
resource "google_service_account" "vm" {
  project      = var.project_id
  account_id   = "${var.name}-vm"
  display_name = "Private web VM (no API privileges)"
}

resource "google_compute_instance_iam_member" "os_login" {
  for_each      = var.ssh_users
  project       = var.project_id
  zone          = var.zone
  instance_name = google_compute_instance.web.name
  role          = "roles/compute.osLogin"
  member        = each.value
}

resource "google_iap_tunnel_instance_iam_member" "ssh" {
  for_each = var.ssh_users
  project  = var.project_id
  zone     = var.zone
  instance = google_compute_instance.web.name
  role     = "roles/iap.tunnelResourceAccessor"
  member   = each.value

  condition {
    title       = "only_this_vm_ssh"
    description = "Permit IAP only to this VM's internal IP and SSH port."
    expression  = "destination.port == 22 && destination.ip == '${google_compute_instance.web.network_interface[0].network_ip}'"
  }
}

# OS Login requires actAs on the attached service account. This grant is scoped
# to the empty-privilege VM identity, not to every service account in the project.
resource "google_service_account_iam_member" "ssh_act_as" {
  for_each           = var.ssh_users
  service_account_id = google_service_account.vm.name
  role               = "roles/iam.serviceAccountUser"
  member             = each.value
}

# gcloud IAP SSH requires these project reads even with instance-scoped login.
# A three-permission custom role avoids Compute Viewer / Instance Admin.
resource "google_project_iam_custom_role" "ssh_discovery" {
  project     = var.project_id
  role_id     = "${replace(var.name, "-", "_")}_ssh_discovery"
  title       = "${var.name} SSH discovery"
  description = "Minimum project reads required by gcloud compute ssh through IAP."
  permissions = ["compute.instances.get", "compute.instances.list", "compute.projects.get"]
}

resource "google_project_iam_member" "ssh_discovery" {
  for_each = var.ssh_users
  project  = var.project_id
  role     = google_project_iam_custom_role.ssh_discovery.name
  member   = each.value
}
