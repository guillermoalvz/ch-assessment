#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: bash bootstrap.sh PROJECT_ID BUCKET_NAME" >&2
  exit 2
fi
state_project="$1"
state_bucket="$2"
if [[ ! "$state_project" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] ||
   [[ ! "$state_bucket" =~ ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$ ]]; then
  echo "Invalid project ID or bucket name." >&2
  exit 2
fi

# Abort if the name already exists; never change an unrelated existing bucket.
# No Terraform operations or state writes happen until versioning is enabled.
gcloud storage buckets create "gs://$state_bucket" \
  --project="$state_project" \
  --location=us-central1 \
  --default-storage-class=STANDARD \
  --uniform-bucket-level-access \
  --public-access-prevention \
  --soft-delete-duration=7d

gcloud storage buckets update "gs://$state_bucket" \
  --project="$state_project" --versioning

echo "Bucket ready. Configure backend.hcl and terraform.tfvars, then initialize and apply state-bootstrap to import it."
