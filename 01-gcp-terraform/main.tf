module "secure_web" {
  #source = "git::https://github.com/guillermoalvz/secure-web.git?ref=v1.0.0"
  source = "./modules/secure_web" # This would be an external repo pinned] by a tag as shown above. For simplicity I've kept it local.

  project_id          = var.project_id
  name                = var.name
  region              = var.region
  zone                = var.zone
  domain_name         = var.domain_name
  ssh_users           = var.ssh_users
  private_subnet_cidr = var.private_subnet_cidr
  boot_image          = var.boot_image

  depends_on = [google_project_service.required]
}
