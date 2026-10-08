resource "google_compute_global_address" "https" {
  project      = var.project_id
  name         = "${var.name}-https-ip"
  address_type = "EXTERNAL"
  ip_version   = "IPV4"
}

resource "google_compute_managed_ssl_certificate" "https" {
  project = var.project_id
  # A content-derived name permits replacement before destruction on domain changes.
  name = "${var.name}-cert-${substr(sha256(var.domain_name), 0, 8)}"

  managed {
    domains = [var.domain_name]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_ssl_policy" "https" {
  project         = var.project_id
  name            = "${var.name}-tls"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
}

resource "google_compute_health_check" "http" {
  project             = var.project_id
  name                = "${var.name}-health"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  http_health_check {
    port         = 80
    request_path = "/healthz"
  }
}

resource "google_compute_backend_service" "web" {
  project               = var.project_id
  name                  = "${var.name}-backend"
  protocol              = "HTTP"
  port_name             = "http"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  timeout_sec           = 30
  health_checks         = [google_compute_health_check.http.id]

  backend {
    group           = google_compute_instance_group.web.id
    balancing_mode  = "UTILIZATION"
    max_utilization = 0.8
  }

  custom_response_headers = [
    "Strict-Transport-Security: max-age=31536000",
    "X-Content-Type-Options: nosniff",
    "X-Frame-Options: DENY",
  ]

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "web" {
  project         = var.project_id
  name            = "${var.name}-url-map"
  default_service = google_compute_backend_service.web.id
}

resource "google_compute_target_https_proxy" "web" {
  project          = var.project_id
  name             = "${var.name}-https-proxy"
  url_map          = google_compute_url_map.web.id
  ssl_certificates = [google_compute_managed_ssl_certificate.https.id]
  ssl_policy       = google_compute_ssl_policy.https.id
  quic_override    = "DISABLE"
}

# Frontend access is controlled by forwarding rules, not VPC firewall rules.
# Only TCP 443 is exposed; there is no HTTP proxy, port 80 rule, or redirect.
resource "google_compute_global_forwarding_rule" "https" {
  project               = var.project_id
  name                  = "${var.name}-https"
  ip_address            = google_compute_global_address.https.address
  ip_protocol           = "TCP"
  port_range            = "443"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  target                = google_compute_target_https_proxy.web.id
}
