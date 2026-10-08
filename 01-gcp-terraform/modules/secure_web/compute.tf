# deletion_protection not enabled since this is deployed in a test project
resource "google_compute_instance" "web" {
  project                   = var.project_id
  name                      = "${var.name}-vm"
  zone                      = var.zone
  machine_type              = "e2-micro"
  can_ip_forward            = false
  allow_stopping_for_update = true
  tags                      = ["${var.name}-backend"]
  labels                    = { purpose = "interview", managed_by = "terraform" }

  boot_disk {
    auto_delete = true
    initialize_params {
      image = var.boot_image
      type  = "pd-standard"
      size  = 10
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.private.id
    network_ip = cidrhost(var.private_subnet_cidr, 10)
    # Deliberately no access_config: the VM has no external IP address.
  }

  service_account {
    email  = google_service_account.vm.email
    scopes = []
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    enable-oslogin           = "TRUE"
    enable-oslogin-2fa       = "TRUE"
    block-project-ssh-keys   = "TRUE"
    serial-port-enable       = "FALSE"
    disable-legacy-endpoints = "TRUE"
  }

  metadata_startup_script = templatefile("${path.module}/templates/startup.sh.tftpl", {
    app_source = file("${path.module}/templates/app.py")
  })

  lifecycle {
    precondition {
      condition     = startswith(var.zone, "${var.region}-")
      error_message = "zone must belong to region; change both when selecting a different region."
    }
  }

  depends_on = [
    google_compute_firewall.http_from_load_balancer,
    google_compute_firewall.ssh_from_iap,
    google_compute_firewall.deny_other_ingress,
    google_compute_firewall.deny_initiated_egress,
    google_compute_route.return_path,
  ]
}

resource "google_compute_instance_group" "web" {
  project   = var.project_id
  name      = "${var.name}-group"
  zone      = var.zone
  instances = [google_compute_instance.web.self_link]

  named_port {
    name = "http"
    port = 80
  }
}
