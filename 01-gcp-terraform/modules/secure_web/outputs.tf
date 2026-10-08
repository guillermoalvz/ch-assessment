output "load_balancer_ip" {
  description = "Global HTTPS frontend IPv4 address."
  value       = google_compute_global_address.https.address
}

output "https_url" {
  description = "DNS hostname protected by a managed TLS certificate."
  value       = "https://${var.domain_name}"
}

output "ssh_command" {
  description = "IAP tunnel with OS Login MFA; repeated connections must not reuse an authenticated SSH session."
  value       = "gcloud compute ssh ${google_compute_instance.web.name} --project=${var.project_id} --zone=${var.zone} --tunnel-through-iap --ssh-key-expire-after=5m -- -o ControlMaster=no -o ControlPath=none -o ControlPersist=no"
}

output "instance_name" {
  description = "Private backend VM."
  value       = google_compute_instance.web.name
}

output "certificate_name" {
  description = "Managed certificate resource."
  value       = google_compute_managed_ssl_certificate.https.name
}

output "backend_service_name" {
  description = "Backend service for health checks."
  value       = google_compute_backend_service.web.name
}
