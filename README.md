# Cloud Security Toolkit

A multi-cloud security assessment toolkit for AWS, Azure, and GCP environments.
Includes tools for S3 bucket enumeration, Azure resource discovery, GCP bucket
scanning, and Infrastructure as Code (IaC) security analysis.

## Overview

| Tool | Description |
|------|-------------|
| `aws_scanner.py` | AWS S3 bucket enumeration — probes bucket name permutations using multi-threaded HTTP requests |
| `azure_scanner.py` | Azure storage account, IMDS, and Key Vault enumeration |
| `gcp_scanner.py` | GCP Cloud Storage bucket, metadata endpoint, and IAM policy checking |
| `cloud_iac_scanner.py` | Static analysis of Terraform and CloudFormation templates for security misconfigurations |

## Installation

```bash
# Clone the repository
git clone https://github.com/ridhinva/Cloud-Security-Toolkit.git
cd Cloud-Security-Toolkit

# Install dependencies
pip install requests
```

Additional dependencies for optional features:
```bash
pip install pyyaml        # CloudFormation YAML parsing (cloud_iac_scanner.py)
pip install google-cloud-resource-manager  # GCP IAM checks (gcp_scanner.py)
```

## Usage

### AWS Scanner — S3 Bucket Enumeration

```bash
# Brute-force common bucket names from a base name
python aws_scanner.py --s3-brute mycompany

# Enumerate S3 buckets derived from a domain
python aws_scanner.py --enum example.com

# Customize worker thread count
python aws_scanner.py --s3-brute mycompany --workers 40
```

**Example output:**
```
[*] Probing 16 bucket names for base: mycompany
[*] Using 20 worker threads

  [+] https://mycompany-backup.s3.amazonaws.com          [EXISTS (403)]
  [+] https://mycompany-logs.s3.amazonaws.com             [PUBLIC]
  [-] https://mycompany-test.s3.amazonaws.com             [NOT FOUND]
  ...

======================================================================
SCAN SUMMARY
======================================================================
  Total buckets probed:   16
  Publicly accessible:     1
  Exists (private):        1
  Not found:              14
```

### Azure Scanner

```bash
# Enumerate Azure Storage Account containers
python azure_scanner.py --storage-enum myaccount

# Check IMDS endpoint (run inside an Azure VM)
python azure_scanner.py --imds-check

# Enumerate Azure Key Vault
python azure_scanner.py --keyvault-enum myvault
```

### GCP Scanner

```bash
# Enumerate GCP Cloud Storage buckets
python gcp_scanner.py --bucket-enum myproject

# Check GCP metadata endpoint (run inside a GCE VM)
python gcp_scanner.py --metadata-check

# Check GCP project IAM policy
python gcp_scanner.py --iam-check my-project-123
```

### IaC Security Scanner

```bash
# Scan a Terraform project directory
python cloud_iac_scanner.py --terraform ./infra/terraform/

# Scan a CloudFormation template
python cloud_iac_scanner.py --cloudformation ./infra/template.yaml

# Scan multiple CloudFormation files
python cloud_iac_scanner.py --cloudformation ./infra/stack.json
```

## How It Works

### AWS Scanner (`aws_scanner.py`)

**S3 Bucket Probing:**

S3 bucket URLs follow the pattern `https://<bucket-name>.s3.amazonaws.com`.
The scanner generates candidate bucket names by combining a user-provided base
name with common suffixes: `test`, `dev`, `prod`, `backup`, `logs`, `data`,
`uploads`, `files`, `static`, `public`, `private`, `temp`, `config`, `images`,
`media`, `assets`.

For example, `--s3-brute mycompany` will probe:
```
mycompany-test.s3.amazonaws.com
mycompany-dev.s3.amazonaws.com
mycompany-prod.s3.amazonaws.com
...
```

For domain enumeration (`--enum example.com`), the tool sanitizes the domain
by replacing dots with hyphens (e.g., `example-com`) and also tries the raw
domain as a bucket name.

**Response Interpretation:**

| HTTP Status | Meaning |
|-------------|---------|
| **200 OK** | Bucket exists AND is publicly listable — data may be exposed |
| **403 Forbidden** | Bucket exists but access is denied (target for further testing) |
| **301 Redirect** | Bucket exists but is in a different AWS region |
| **404 Not Found** | Bucket does not exist |
| Other | Rare edge cases; bucket likely doesn't exist |

**Multi-threading:**

Uses `concurrent.futures.ThreadPoolExecutor` with a configurable number of
worker threads (default: 20). Each bucket probe is submitted as a separate
future, and results are collected as they complete using `as_completed()`.
This enables scanning dozens of bucket names in seconds.

**Use Cases:**
- Reconnaissance during penetration testing
- Evaluating an organization's S3 security posture
- Identifying data leaks from misconfigured S3 buckets

### Azure Scanner (`azure_scanner.py`)

**Storage Enumeration:**
Azure Blob Storage follows the pattern
`https://<account>.blob.core.windows.net/<container>`.
The scanner probes common container names and checks for public access.
A 200 response with an XML listing of blobs confirms the container is
publicly readable — a significant data exposure risk.

**IMDS Check:**
Azure's Instance Metadata Service lives at
`http://169.254.169.254/metadata/instance?api-version=2021-02-01`
and requires the `Metadata: true` header. This endpoint exposes sensitive
VM metadata including network configuration, subscription details, and
managed identity tokens. If an SSRF vulnerability lets an attacker reach
the internal network, they can query this endpoint without authentication.

**Key Vault Enumeration:**
Azure Key Vault DNS follows the pattern
`https://<vault>.vault.azure.net/`. The scanner checks vault existence
and probes for common secret/ key names. A misconfigured access policy
or network ACL can expose sensitive secrets.

### GCP Scanner (`gcp_scanner.py`)

**Bucket Enumeration:**
GCP Cloud Storage uses
`https://storage.googleapis.com/<bucket-name>/`.
Similar to the AWS S3 scanner, it generates candidate names from
common suffixes and probes each one. Response codes follow the same
interpretation (200 = public, 403 = exists but private, 404 = not found).

**Metadata Check:**
GCE's metadata endpoint at
`http://metadata.google.internal/computeMetadata/v1/`
requires the `Metadata-Flavor: Google` header. This is the GCP equivalent
of the IMDS SSRF attack — it leaks instance identity, service account
tokens, and custom metadata (which often contains secrets).

**IAM Check:**
Calls `gcloud projects get-iam-policy <project_id>` to retrieve the
project's IAM policy and checks for:
- `allUsers` or `allAuthenticatedUsers` bindings (public access)
- Wildcard (`*`) actions on service accounts
- Overly permissive roles assigned to service accounts

### IaC Scanner (`cloud_iac_scanner.py`)

**Terraform Analysis:**
Walks the specified directory tree, finds all `.tf` files, and parses
resource blocks using regex-based pattern matching. Checks for:
- `aws_s3_bucket` without `server_side_encryption_configuration`
- `aws_s3_bucket` with `acl = "public-read"` or `"public-read-write"`
- `aws_security_group` with `cidr_blocks = ["0.0.0.0/0"]`
- `aws_db_instance` with `publicly_accessible = true`
- `aws_iam_role_policy` with `Action = "*"` and `Effect = "Allow"`
- `aws_ebs_volume` with `encrypted = false`

**CloudFormation Analysis:**
Parses JSON and YAML templates into Python dictionaries, then walks the
`Resources` section checking each resource type against known security
rules. Detects:
- `AWS::S3::Bucket` with `PublicRead` or `PublicReadWrite` AccessControl
- `AWS::EC2::SecurityGroup` with `CidrIp: 0.0.0.0/0`
- `AWS::RDS::DBInstance` with `PubliclyAccessible: true`
- `AWS::S3::Bucket` missing `BucketEncryption`
- `AWS::IAM::Policy` with `Action: "*"`

Findings are categorized by severity:
- **CRITICAL**: Public resource exposure (public S3, open security groups)
- **HIGH**: Missing encryption, wildcard IAM actions
- **MEDIUM**: Non-critical misconfigurations
- **LOW**: Best practice recommendations

## License

MIT
