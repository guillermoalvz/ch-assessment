# Application Default Credentials; never put keys or tokens in Terraform.
provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}
