output "monthly_budget_id" {
  description = "Project-scoped budget with actual and forecast alerts in the account currency."
  value       = google_billing_budget.monthly.id
}

output "alert_amounts" {
  description = "Actual and forecast thresholds, explicitly denominated in the billing account currency."
  value = {
    currency_code = local.currency_code
    lower         = var.monthly_budget_amount * 0.2
    upper         = var.monthly_budget_amount
  }
}

output "monthly_spike_budget_id" {
  description = "Relative monthly actual/forecast spike budget; needs a previous-month baseline."
  value       = google_billing_budget.monthly_spike.id
}
