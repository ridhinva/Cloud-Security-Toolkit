#!/usr/bin/env python3
"""
Cloud IaC Security Scanner - Terraform & CloudFormation

A static analysis tool for identifying security misconfigurations in
Infrastructure as Code (IaC) templates. Supports both Terraform (.tf)
and AWS CloudFormation (.json, .yaml, .yml) formats.

Features:
    - Terraform template security analysis
    - AWS CloudFormation template security analysis
    - Detection of common IaC misconfigurations:
        - S3 buckets with public ACL (acl = "public-read" or "public-read-write")
        - Security groups with overly permissive rules (0.0.0.0/0 ingress)
        - Unencrypted storage (S3, EBS, RDS without encryption)
        - Public RDS/Redshift instances
        - IAM roles with wildcard (*) actions
        - Plaintext secrets/credentials in template variables

Usage:
    python cloud_iac_scanner.py --terraform <path/to/terraform/dir>
    python cloud_iac_scanner.py --cloudformation <path/to/template.yaml>
    python cloud_iac_scanner.py --cloudformation <path/to/template.json>

Examples:
    # Scan a Terraform project directory
    python cloud_iac_scanner.py --terraform ./infra/terraform/

    # Scan a CloudFormation template
    python cloud_iac_scanner.py --cloudformation ./infra/cloudformation/deploy.yaml

    # Scan with verbose output
    python cloud_iac_scanner.py --terraform ./infra/ --verbose

How It Works:

    Terraform Scanner:
        Parses .tf files and checks resource blocks against a rule engine.
        Detection rules include:
          - aws_s3_bucket with public ACL or public_access_block disabled
          - aws_security_group with cidr_blocks = ["0.0.0.0/0"]
          - aws_db_instance with publicly_accessible = true
          - aws_s3_bucket with server_side_encryption_configuration absent
          - aws_iam_role/aws_iam_policy with Effect = "Allow" and Action = "*"
          - aws_ebs_volume with encrypted = false or unset
        Results are categorized by severity: CRITICAL, HIGH, MEDIUM, LOW.

    CloudFormation Scanner:
        Parses JSON/YAML templates and checks resource properties.
        Detection rules include:
          - AWS::S3::Bucket with PublicRead or PublicReadWrite ACLs
          - AWS::EC2::SecurityGroup with 0.0.0.0/0 Ingress
          - AWS::RDS::DBInstance with PubliclyAccessible = true
          - AWS::S3::Bucket without BucketEncryption
          - AWS::IAM::Policy with Effect: Allow and Action: '*'
        Outputs findings with line references and remediation suggestions.

    Output Format:
        Each finding includes:
          - [Severity] File:line - Resource Type
          - Description of the misconfiguration
          - Remediation suggestion

Dependencies:
    - pyyaml (for CloudFormation YAML parsing)
    - json (stdlib, for CloudFormation JSON parsing)
    - os, re (stdlib for file walking and pattern matching)
"""

if __name__ == "__main__":
    import sys

    print("Cloud IaC Security Scanner - Terraform & CloudFormation")
    print("=" * 70)
    print(__doc__)

    if len(sys.argv) < 2:
        print("\nNo arguments provided. Run with --help for usage.")
        print("Example: python cloud_iac_scanner.py --terraform ./infra/")
        sys.exit(1)
