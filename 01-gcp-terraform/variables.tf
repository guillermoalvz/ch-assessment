variable "project_id" {
  description = "Existing GCP project with billing enabled."
  type        = string
  nullable    = false
}

variable "name" {
  description = "Resource name prefix (also used for the dedicated service account)."
  type        = string
  default     = "interview-web"
  nullable    = false
}

variable "region" {
  description = "One of the three Compute Engine Free Tier regions."
  type        = string
  default     = "us-central1"
  nullable    = false
}

variable "zone" {
  description = "E2-capable zone within the selected region."
  type        = string
  default     = "us-central1-a"
  nullable    = false
}

variable "domain_name" {
  description = "DNS hostname you control; its A record must point at the load balancer IP."
  type        = string
  nullable    = false
}

variable "ssh_users" {
  description = "Explicit human IAM principals (user:email) with Google Account 2-Step Verification enabled."
  type        = set(string)
  nullable    = false
}

variable "private_subnet_cidr" {
  description = "Private VM tier RFC1918 /24."
  type        = string
  default     = "10.20.20.0/24"
  nullable    = false
}

variable "boot_image" {
  description = "Ubuntu 24.04 image family or a pinned compatible image with Python 3 and Google OS Login installed."
  type        = string
  default     = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
  nullable    = false
}
