resource "google_compute_network" "vpc" {
  project                         = var.project_id
  name                            = "${var.name}-vpc"
  auto_create_subnetworks         = false
  routing_mode                    = "REGIONAL"
  delete_default_routes_on_create = true
}

# A public subnet is not needed: the GLOBAL external load balancer runs on
# Google's edge, outside the VPC. Only its private VM backend needs a subnet.
resource "google_compute_subnetwork" "private" {
  project                  = var.project_id
  name                     = "${var.name}-private"
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = var.private_subnet_cidr
  stack_type               = "IPV4_ONLY"
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.1
    metadata             = "EXCLUDE_ALL_METADATA"
  }

}

# Required for return traffic to GFE/IAP. A route does not grant internet
# access: the VM has no external IP or NAT and all initiated egress is denied.
resource "google_compute_route" "return_path" {
  project          = var.project_id
  name             = "${var.name}-return-path"
  network          = google_compute_network.vpc.id
  dest_range       = "0.0.0.0/0"
  next_hop_gateway = "default-internet-gateway"
  priority         = 1000
  tags             = ["${var.name}-backend"]
}
