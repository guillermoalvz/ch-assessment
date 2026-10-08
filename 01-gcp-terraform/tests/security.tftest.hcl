# All calls use an in-memory mocked provider; these tests never touch GCP resources.
mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      email = "interview-web-vm@test-project.iam.gserviceaccount.com"
      name  = "projects/test-project/serviceAccounts/interview-web-vm@test-project.iam.gserviceaccount.com"
    }
  }
}

variables {
  project_id  = "test-project"
  domain_name = "app.example.com"
  ssh_users   = ["user:engineer@example.com"]
}

run "root_wiring" {
  command = plan

  assert {
    condition     = module.secure_web.https_url == "https://app.example.com"
    error_message = "The root must expose the HTTPS module endpoint."
  }

  assert {
    condition     = alltrue([for api in google_project_service.required : !api.disable_on_destroy])
    error_message = "Destroying this stack must not disable shared project APIs."
  }
}

run "secure_architecture" {
  command = apply

  module {
    source = "./modules/secure_web"
  }

  assert {
    condition = (
      !google_compute_network.vpc.auto_create_subnetworks &&
      google_compute_subnetwork.private.private_ip_google_access &&
      google_compute_instance.web.network_interface[0].subnetwork == google_compute_subnetwork.private.id &&
      length(google_compute_instance.web.network_interface[0].access_config) == 0
    )
    error_message = "The backend must use a custom VPC's private subnet with no public IP."
  }

  assert {
    condition = (
      google_compute_instance.web.machine_type == "e2-micro" &&
      google_compute_instance.web.zone == "us-central1-a" &&
      google_compute_instance.web.boot_disk[0].initialize_params[0].type == "pd-standard" &&
      google_compute_instance.web.boot_disk[0].initialize_params[0].size <= 30
    )
    error_message = "Default VM and disk configuration must stay within Free Tier specifications."
  }

  assert {
    condition = (
      google_compute_global_forwarding_rule.https.port_range == "443" &&
      google_compute_global_forwarding_rule.https.ip_protocol == "TCP" &&
      google_compute_global_forwarding_rule.https.load_balancing_scheme == "EXTERNAL_MANAGED" &&
      google_compute_global_forwarding_rule.https.target == google_compute_target_https_proxy.web.id &&
      google_compute_ssl_policy.https.min_tls_version == "TLS_1_2" &&
      google_compute_target_https_proxy.web.quic_override == "DISABLE"
    )
    error_message = "The global frontend must expose only TCP 443 with modern TLS."
  }

  assert {
    condition = (
      google_compute_backend_service.web.protocol == "HTTP" &&
      one(google_compute_backend_service.web.backend).group == google_compute_instance_group.web.id &&
      contains(google_compute_instance_group.web.instances, google_compute_instance.web.self_link) &&
      google_compute_instance_group.web.named_port[0].port == 80 &&
      google_compute_health_check.http.http_health_check[0].port == 80 &&
      google_compute_health_check.http.http_health_check[0].request_path == "/healthz"
    )
    error_message = "Frontend routing and health probes must reach this VM on HTTP 80."
  }

  assert {
    condition = (
      google_compute_firewall.ssh_from_iap.direction == "INGRESS" &&
      google_compute_firewall.ssh_from_iap.source_ranges == toset(["35.235.240.0/20"]) &&
      one(google_compute_firewall.ssh_from_iap.allow).protocol == "tcp" &&
      one(google_compute_firewall.ssh_from_iap.allow).ports == tolist(["22"]) &&
      google_compute_firewall.http_from_load_balancer.source_ranges == toset(["35.191.0.0/16", "130.211.0.0/22"]) &&
      one(google_compute_firewall.http_from_load_balancer.allow).protocol == "tcp" &&
      one(google_compute_firewall.http_from_load_balancer.allow).ports == tolist(["80"]) &&
      google_compute_firewall.ssh_from_iap.target_service_accounts == toset([google_service_account.vm.email]) &&
      google_compute_firewall.http_from_load_balancer.target_service_accounts == toset([google_service_account.vm.email])
    )
    error_message = "Allow only IAP SSH and GFE/health-check HTTP to the dedicated VM identity."
  }

  assert {
    condition = (
      google_compute_firewall.deny_other_ingress.priority > google_compute_firewall.ssh_from_iap.priority &&
      one(google_compute_firewall.deny_other_ingress.deny).protocol == "all" &&
      google_compute_firewall.deny_initiated_egress.direction == "EGRESS" &&
      one(google_compute_firewall.deny_initiated_egress.deny).protocol == "all"
    )
    error_message = "Deny other ingress and initiated egress."
  }

  assert {
    condition = (
      google_compute_instance.web.metadata["enable-oslogin"] == "TRUE" &&
      google_compute_instance.web.metadata["enable-oslogin-2fa"] == "TRUE" &&
      google_compute_instance.web.metadata["block-project-ssh-keys"] == "TRUE" &&
      google_compute_instance.web.metadata["serial-port-enable"] == "FALSE" &&
      google_compute_instance.web.shielded_instance_config[0].enable_secure_boot &&
      google_compute_instance.web.shielded_instance_config[0].enable_vtpm &&
      google_compute_instance.web.shielded_instance_config[0].enable_integrity_monitoring
    )
    error_message = "OS Login MFA and Shielded VM controls must remain enabled."
  }

  assert {
    condition = (
      length(google_compute_instance.web.service_account[0].scopes) == 0 &&
      google_compute_instance_iam_member.os_login["user:engineer@example.com"].role == "roles/compute.osLogin" &&
      google_compute_instance_iam_member.os_login["user:engineer@example.com"].instance_name == google_compute_instance.web.name &&
      google_service_account_iam_member.ssh_act_as["user:engineer@example.com"].service_account_id == google_service_account.vm.name &&
      google_iap_tunnel_instance_iam_member.ssh["user:engineer@example.com"].condition[0].expression == "destination.port == 22 && destination.ip == '10.20.20.10'" &&
      google_project_iam_custom_role.ssh_discovery.permissions == toset(["compute.instances.get", "compute.instances.list", "compute.projects.get"])
    )
    error_message = "SSH users get instance-level non-sudo login, restricted IAP and only necessary discovery/actAs permissions."
  }

  assert {
    condition = (
      strcontains(google_compute_instance.web.metadata_startup_script, "AuthorizedKeysFile none") &&
      strcontains(google_compute_instance.web.metadata_startup_script, "DynamicUser=yes") &&
      strcontains(output.ssh_command, "ControlPath=none")
    )
    error_message = "Disable local SSH keys and session reuse and run the application without root."
  }
}

run "reject_service_account_ssh" {
  command = plan
  module {
    source = "./modules/secure_web"
  }
  variables {
    ssh_users = ["serviceAccount:automation@test-project.iam.gserviceaccount.com"]
  }
  expect_failures = [var.ssh_users]
}

run "reject_service_account_disguised_as_user" {
  command = plan
  module {
    source = "./modules/secure_web"
  }
  variables {
    ssh_users = ["user:automation@test-project.iam.gserviceaccount.com"]
  }
  expect_failures = [var.ssh_users]
}

run "reject_group_ssh" {
  command = plan
  module {
    source = "./modules/secure_web"
  }
  variables {
    ssh_users = ["group:engineers@example.com"]
  }
  expect_failures = [var.ssh_users]
}

run "reject_empty_ssh_users" {
  command = plan
  module {
    source = "./modules/secure_web"
  }
  variables {
    ssh_users = []
  }
  expect_failures = [var.ssh_users]
}

run "reject_public_cidr" {
  command = plan
  module {
    source = "./modules/secure_web"
  }
  variables {
    private_subnet_cidr = "8.8.8.0/24"
  }
  expect_failures = [var.private_subnet_cidr]
}

run "reject_noncanonical_cidr" {
  command = plan
  module {
    source = "./modules/secure_web"
  }
  variables {
    private_subnet_cidr = "10.20.20.1/24"
  }
  expect_failures = [var.private_subnet_cidr]
}

run "reject_zone_region_mismatch" {
  command = plan
  module {
    source = "./modules/secure_web"
  }
  variables {
    zone = "us-east1-b"
  }
  expect_failures = [google_compute_instance.web]
}
