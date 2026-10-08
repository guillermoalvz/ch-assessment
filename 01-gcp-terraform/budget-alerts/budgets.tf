locals {
  monitored_projects = ["projects/${data.google_project.target.number}"]
  currency_code      = data.google_billing_account.target.currency_code
  # 20% and 100% of a 5-unit monthly budget are exactly 1 and 5 units,
  # denominated in the billing account's currency (not necessarily USD).
  thresholds = {
    actual_1   = { fraction = 0.2, basis = "CURRENT_SPEND" }
    actual_5   = { fraction = 1.0, basis = "CURRENT_SPEND" }
    forecast_1 = { fraction = 0.2, basis = "FORECASTED_SPEND" }
    forecast_5 = { fraction = 1.0, basis = "FORECASTED_SPEND" }
  }
}

resource "google_billing_budget" "monthly" {
  billing_account = var.billing_account_id
  display_name    = "${var.project_id}: ${local.currency_code} budget alerts"

  budget_filter {
    projects               = local.monitored_projects
    calendar_period        = "MONTH"
    credit_types_treatment = "INCLUDE_SPECIFIED_CREDITS"
    credit_types           = ["FREE_TIER"]
    # Trial PROMOTION credits intentionally excluded; retain Free Tier savings.
  }

  amount {
    specified_amount {
      currency_code = local.currency_code
      units         = tostring(floor(var.monthly_budget_amount))
      nanos         = floor((var.monthly_budget_amount - floor(var.monthly_budget_amount)) * 1000000000 + 0.5)
    }
  }

  dynamic "threshold_rules" {
    for_each = local.thresholds
    content {
      threshold_percent = threshold_rules.value.fraction
      spend_basis       = threshold_rules.value.basis
    }
  }

  all_updates_rule {
    disable_default_iam_recipients = false
    monitoring_notification_channels = [
      for channel in google_monitoring_notification_channel.email : channel.name
    ]
  }

  depends_on = [google_project_service.required]
}

# Absolute thresholds alone stop warning about growth once already exceeded.
# This separate budget warns about rising monthly cost relative to last month.
# It needs a previous-period baseline and is not a real-time hourly detector.
resource "google_billing_budget" "monthly_spike" {
  billing_account = var.billing_account_id
  display_name    = "${var.project_id}: monthly cost increase"

  budget_filter {
    projects               = local.monitored_projects
    calendar_period        = "MONTH"
    credit_types_treatment = "INCLUDE_SPECIFIED_CREDITS"
    credit_types           = ["FREE_TIER"]
  }

  amount {
    last_period_amount = true
  }

  threshold_rules {
    threshold_percent = var.monthly_spike_multiplier
    spend_basis       = "CURRENT_SPEND"
  }

  threshold_rules {
    threshold_percent = var.monthly_spike_multiplier
    spend_basis       = "FORECASTED_SPEND"
  }

  all_updates_rule {
    disable_default_iam_recipients = false
    monitoring_notification_channels = [
      for channel in google_monitoring_notification_channel.email : channel.name
    ]
  }

  depends_on = [google_project_service.required]
}
