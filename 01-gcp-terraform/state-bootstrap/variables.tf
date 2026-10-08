variable "project_id" {
  description = "Existing project hosting the state bucket."
  type        = string
  nullable    = false
}

variable "bucket_name" {
  description = "Globally unique existing bucket created with bootstrap.sh."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "Use a 3-63 character bucket name with lowercase letters, digits and hyphens."
  }
}

variable "state_principals" {
  description = "Explicit trusted Terraform users or service accounts; never the VM service account or public principals."
  type        = set(string)
  nullable    = false

  validation {
    condition = length(var.state_principals) > 0 && alltrue([
      for member in var.state_principals : can(regex("^(user|serviceAccount):[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", member))
    ])
    error_message = "Supply at least one explicit user:email or serviceAccount:email for state access."
  }
}
