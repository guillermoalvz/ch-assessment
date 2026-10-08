output "load_balancer_ip" {
  description = "Publish this address as the domain's DNS A record."
  value       = module.secure_web.load_balancer_ip
}

output "https_url" {
  description = "Available after DNS propagation, certificate activation, and backend readiness."
  value       = module.secure_web.https_url
}

output "ssh_command" {
  description = "IAP SSH command; OS Login prompts for a second factor."
  value       = module.secure_web.ssh_command
}

output "instance_name" {
  description = "Private backend VM name."
  value       = module.secure_web.instance_name
}

output "certificate_name" {
  description = "Google-managed certificate to inspect during provisioning."
  value       = module.secure_web.certificate_name
}

output "backend_service_name" {
  description = "Global backend service to inspect health."
  value       = module.secure_web.backend_service_name
}
