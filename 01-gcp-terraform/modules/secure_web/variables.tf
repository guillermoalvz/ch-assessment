variable "project_id" {
  description = "Existing GCP project ID."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Supply a valid GCP project ID (6-30 lowercase letters, digits, or hyphens)."
  }
}

variable "name" {
  description = "Resource prefix; limited so the service account ID remains within 30 characters."
  type        = string
  default     = "interview-web"
  nullable    = false

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,21}[a-z0-9]$", var.name))
    error_message = "name must contain 4-23 lowercase letters, digits, or hyphens, starting with a letter and ending with a letter or digit."
  }
}

variable "region" {
  description = "Compute Engine Free Tier eligible region."
  type        = string
  default     = "us-central1"
  nullable    = false

  validation {
    condition     = contains(["us-central1", "us-east1", "us-west1"], var.region)
    error_message = "Choose us-central1, us-east1, or us-west1 for Free Tier eligibility."
  }
}

variable "zone" {
  description = "E2-capable zone in region."
  type        = string
  default     = "us-central1-a"
  nullable    = false

  validation {
    condition     = can(regex("^us-(central1|east1|west1)-[a-f]$", var.zone))
    error_message = "Supply a US zone within a supported region."
  }
}

variable "domain_name" {
  description = "DNS hostname for the Google-managed certificate (no scheme, wildcard, or trailing dot)."
  type        = string
  nullable    = false

  validation {
    condition     = length(var.domain_name) <= 253 && can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", var.domain_name))
    error_message = "Supply a lowercase DNS hostname such as app.example.com."
  }
}

variable "ssh_users" {
  description = "Human user:email principals only. Service accounts bypass OS Login 2FA and must not be granted SSH."
  type        = set(string)
  nullable    = false

  validation {
    condition = length(var.ssh_users) > 0 && alltrue([
      for member in var.ssh_users : can(regex("^user:[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", member)) && !endswith(lower(member), ".gserviceaccount.com")
    ])
    error_message = "Provide at least one explicit human user:email; groups and service accounts are excluded to preserve MFA."
  }
}

variable "private_subnet_cidr" {
  description = "Private-tier /24 in RFC1918 space."
  type        = string
  default     = "10.20.20.0/24"
  nullable    = false

  validation {
    condition = can(cidrnetmask(var.private_subnet_cidr)) && can(regex("/24$", var.private_subnet_cidr)) && anytrue([
      can(regex("^10\\.", var.private_subnet_cidr)),
      can(regex("^172\\.(1[6-9]|2[0-9]|3[01])\\.", var.private_subnet_cidr)),
      can(regex("^192\\.168\\.", var.private_subnet_cidr)),
    ]) && try(cidrhost(var.private_subnet_cidr, 0) == split("/", var.private_subnet_cidr)[0], false)
    error_message = "private_subnet_cidr must be a canonical IPv4 RFC1918 /24."
  }
}

variable "boot_image" {
  description = "Compatible Ubuntu image with Python 3 and Google OS Login. Pin a tested image for repeatable production builds."
  type        = string
  default     = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
  nullable    = false
}
