mock_provider "google" {
  mock_data "google_project" {
    defaults = {
      number = "123456789012"
    }
  }
  mock_data "google_billing_account" {
    defaults = {
      currency_code = "USD"
    }
  }
}

variables {
  project_id          = "test-project"
  billing_account_id  = "012345-ABCDEF-012345"
  notification_emails = ["engineer@example.com"]
}

run "actual_forecast_and_relative_spike_alerts" {
  command = apply

  assert {
    condition = (
      google_billing_budget.monthly.amount[0].specified_amount[0].currency_code == "USD" &&
      google_billing_budget.monthly.amount[0].specified_amount[0].units == "5" &&
      toset([for rule in google_billing_budget.monthly.threshold_rules : "${rule.spend_basis}:${rule.threshold_percent}"]) ==
      toset(["CURRENT_SPEND:0.2", "CURRENT_SPEND:1", "FORECASTED_SPEND:0.2", "FORECASTED_SPEND:1"])
    )
    error_message = "Budget must alert at exactly USD 1 and USD 5 for both actual and forecast spend."
  }

  assert {
    condition = alltrue([
      for budget in [google_billing_budget.monthly, google_billing_budget.monthly_spike] :
      toset(budget.budget_filter[0].projects) == toset(["projects/123456789012"]) &&
      budget.budget_filter[0].calendar_period == "MONTH" &&
      budget.budget_filter[0].credit_types_treatment == "INCLUDE_SPECIFIED_CREDITS" &&
      toset(budget.budget_filter[0].credit_types) == toset(["FREE_TIER"]) &&
      !budget.all_updates_rule[0].disable_default_iam_recipients &&
      length(budget.all_updates_rule[0].monitoring_notification_channels) == 1
    ])
    error_message = "Monitor only the target project; preserve Free Tier credits and recipients, but exclude trial credits."
  }

  assert {
    condition = (
      google_billing_budget.monthly_spike.amount[0].last_period_amount &&
      length(google_billing_budget.monthly_spike.threshold_rules) == 2 &&
      alltrue([for rule in google_billing_budget.monthly_spike.threshold_rules : rule.threshold_percent == 1.5]) &&
      toset([for rule in google_billing_budget.monthly_spike.threshold_rules : rule.spend_basis]) == toset(["CURRENT_SPEND", "FORECASTED_SPEND"])
    )
    error_message = "Relative alerts must warn at a 50% monthly increase for both actual and forecast costs."
  }

  assert {
    condition = (
      google_monitoring_notification_channel.email["engineer@example.com"].type == "email" &&
      google_monitoring_notification_channel.email["engineer@example.com"].enabled &&
      google_monitoring_notification_channel.email["engineer@example.com"].labels.email_address == "engineer@example.com"
    )
    error_message = "The explicit recipient must have an enabled email notification channel."
  }
}

run "default_recipients_without_extra_emails" {
  command = apply
  variables {
    notification_emails = []
  }
  assert {
    condition = (
      length(google_monitoring_notification_channel.email) == 0 &&
      !google_billing_budget.monthly.all_updates_rule[0].disable_default_iam_recipients
    )
    error_message = "Leaving additional recipients empty must still email billing admins and users."
  }
}

run "account_currency_eur" {
  command = apply

  override_data {
    target = data.google_billing_account.target
    values = {
      currency_code = "EUR"
    }
  }

  assert {
    condition = (
      google_billing_budget.monthly.amount[0].specified_amount[0].currency_code == "EUR" &&
      google_billing_budget.monthly.amount[0].specified_amount[0].units == "5" &&
      google_billing_budget.monthly.amount[0].specified_amount[0].nanos == 0 &&
      output.alert_amounts.currency_code == "EUR" &&
      output.alert_amounts.lower == 1 && output.alert_amounts.upper == 5 &&
      !strcontains(google_billing_budget.monthly.display_name, "USD") &&
      !data.google_billing_account.target.lookup_projects
    )
    error_message = "Read the account currency and create EUR 1 / EUR 5 alerts on a EUR account, without extra project discovery."
  }
}

run "fractional_budget_in_account_currency" {
  command = apply
  variables {
    monthly_budget_amount = 4.25
  }
  override_data {
    target = data.google_billing_account.target
    values = {
      currency_code = "EUR"
    }
  }
  assert {
    condition = (
      google_billing_budget.monthly.amount[0].specified_amount[0].currency_code == "EUR" &&
      google_billing_budget.monthly.amount[0].specified_amount[0].units == "4" &&
      google_billing_budget.monthly.amount[0].specified_amount[0].nanos == 250000000 &&
      output.alert_amounts.lower == 0.85 && output.alert_amounts.upper == 4.25
    )
    error_message = "Fractional budgets must be encoded with correct Money units and nanos."
  }
}

run "reject_zero_budget" {
  command = plan
  variables {
    monthly_budget_amount = 0
  }
  expect_failures = [var.monthly_budget_amount]
}

run "reject_excess_precision" {
  command = plan
  variables {
    monthly_budget_amount = 4.251
  }
  expect_failures = [var.monthly_budget_amount]
}

run "reject_invalid_billing_account" {
  command = plan
  variables {
    billing_account_id = "not-an-account"
  }
  expect_failures = [var.billing_account_id]
}

run "reject_too_many_recipients" {
  command = plan
  variables {
    notification_emails = ["a@example.com", "b@example.com", "c@example.com", "d@example.com", "e@example.com", "f@example.com"]
  }
  expect_failures = [var.notification_emails]
}

run "reject_non_spike_multiplier" {
  command = plan
  variables {
    monthly_spike_multiplier = 1
  }
  expect_failures = [var.monthly_spike_multiplier]
}
