locals {
  # Published GFE and health-check source ranges for global instance-group backends.
  load_balancer_ranges = ["35.191.0.0/16", "130.211.0.0/22"]
  iap_range            = "35.235.240.0/20"
}

resource "google_compute_firewall" "http_from_load_balancer" {
  project                 = var.project_id
  name                    = "${var.name}-http-from-gfe"
  network                 = google_compute_network.vpc.id
  direction               = "INGRESS"
  priority                = 1000
  source_ranges           = local.load_balancer_ranges
  target_service_accounts = [google_service_account.vm.email]

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  log_config {
    metadata = "EXCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "ssh_from_iap" {
  project                 = var.project_id
  name                    = "${var.name}-ssh-from-iap"
  network                 = google_compute_network.vpc.id
  direction               = "INGRESS"
  priority                = 1000
  source_ranges           = [local.iap_range]
  target_service_accounts = [google_service_account.vm.email]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  log_config {
    metadata = "EXCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "deny_other_ingress" {
  project                 = var.project_id
  name                    = "${var.name}-deny-other-ingress"
  network                 = google_compute_network.vpc.id
  direction               = "INGRESS"
  priority                = 65534
  source_ranges           = ["0.0.0.0/0"]
  target_service_accounts = [google_service_account.vm.email]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "EXCLUDE_ALL_METADATA"
  }
}

# Stateful firewall rules permit replies to allowed ingress. OS Login, DNS,
# DHCP and NTP use the metadata server, which GCP exempts from VPC filtering.
# Bootstrap uses installed software, so neither Cloud NAT nor apt access is needed.
resource "google_compute_firewall" "deny_initiated_egress" {
  project                 = var.project_id
  name                    = "${var.name}-deny-egress"
  network                 = google_compute_network.vpc.id
  direction               = "EGRESS"
  priority                = 1000
  destination_ranges      = ["0.0.0.0/0"]
  target_service_accounts = [google_service_account.vm.email]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "EXCLUDE_ALL_METADATA"
  }
}
