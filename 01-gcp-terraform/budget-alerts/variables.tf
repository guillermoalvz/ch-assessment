variable "project_id" {
  description = "Project to monitor, also used as the API quota project."
  type        = string
  nullable    = false
}

variable "billing_account_id" {
  description = "Linked billing account ID; omit the billingAccounts/ prefix. Its currency is detected automatically."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[A-Fa-f0-9]{6}-[A-Fa-f0-9]{6}-[A-Fa-f0-9]{6}$", var.billing_account_id))
    error_message = "Use the billing account ID format XXXXXX-XXXXXX-XXXXXX."
  }
}

variable "monthly_budget_amount" {
  description = "Monthly budget in the account currency; alerts at 20% and 100%. Default 5 gives 1 and 5 currency units."
  type        = number
  default     = 5
  nullable    = false

  validation {
    condition     = var.monthly_budget_amount >= 0.05 && can(regex("^[0-9]+(\\.[0-9]{1,2})?$", tostring(var.monthly_budget_amount)))
    error_message = "Set a positive budget of at least 0.05, with no more than two decimal places, in the billing account currency."
  }
}

variable "notification_emails" {
  description = "Optional additional email recipients; billing admins/users always remain recipients."
  type        = set(string)
  default     = []
  nullable    = false

  validation {
    condition = length(var.notification_emails) <= 5 && alltrue([
      for email in var.notification_emails : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", email))
    ])
    error_message = "Specify at most five valid email addresses."
  }
}

variable "monthly_spike_multiplier" {
  description = "Relative warning threshold against the previous calendar month's cost. 1.5 means a 50% increase."
  type        = number
  default     = 1.5
  nullable    = false

  validation {
    condition     = var.monthly_spike_multiplier > 1 && var.monthly_spike_multiplier <= 10
    error_message = "Choose a relative spike multiplier greater than 1 and at most 10."
  }
}
