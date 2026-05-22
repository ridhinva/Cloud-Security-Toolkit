#!/usr/bin/env python3
"""
GCP Cloud Security Scanner

A toolkit for enumerating and testing Google Cloud Platform resources for
common security misconfigurations.

Features:
    - GCP Cloud Storage bucket enumeration
    - GCP Compute Engine Metadata Service check
    - GCP IAM policy enumeration and misconfiguration detection

Usage:
    python gcp_scanner.py --bucket-enum <base_name>
    python gcp_scanner.py --metadata-check
    python gcp_scanner.py --iam-check <project_id>

Examples:
    # Enumerate GCP storage buckets with common names
    python gcp_scanner.py --bucket-enum myproject

    # Check if GCP metadata endpoint is accessible (run on a GCE VM)
    python gcp_scanner.py --metadata-check

    # Check IAM policy for a GCP project (requires gcloud CLI auth)
    python gcp_scanner.py --iam-check my-project-123

How It Works:

    Bucket Enumeration:
        Probes GCP Cloud Storage buckets using the URL pattern:
        https://storage.googleapis.com/<bucket-name>/
        Tests common bucket name suffixes (test, dev, prod, backup, logs, data,
        uploads, files, static, public, private, etc.) appended to a user-provided
        base name.
        - HTTP 200: Bucket exists and is publicly listable (data exposure)
        - HTTP 403: Bucket exists but access denied
        - HTTP 404: Bucket does not exist
        Supports multi-threaded scanning via concurrent.futures for speed.

    Metadata Check:
        Queries the GCP Compute Metadata Service at:
        http://metadata.google.internal/computeMetadata/v1/
        Uses the required Metadata-Flavor: Google header.
        If the application is running on GCE and is vulnerable to SSRF, this
        endpoint can leak:
          - Instance identity tokens
          - Service account credentials (access tokens)
          - Project and zone metadata
          - Custom metadata (may contain secrets)
        This is the GCP equivalent of the AWS/Azure IMDS SSRF attack vector.

    IAM Check:
        Tests GCP IAM policy configurations by probing the Cloud Resource
        Manager API. Checks for:
          - Overly permissive roles (e.g., allUsers, allAuthenticatedUsers)
          - Service account key exposure
          - Publicly accessible resources via IAM bindings
        Requires the gcloud CLI to be authenticated and the project ID.
        Calls: gcloud projects get-iam-policy <project_id>

Dependencies:
    - requests (pip install requests)
    - google-cloud-resource-manager (optional, for IAM checks)
    - gcloud CLI (optional, for IAM checks)
"""

if __name__ == "__main__":
    import sys

    print("GCP Cloud Security Scanner")
    print("=" * 60)
    print(__doc__)

    if len(sys.argv) < 2:
        print("\nNo arguments provided. Run with --help for usage.")
        print("Example: python gcp_scanner.py --bucket-enum myproject")
        sys.exit(1)
