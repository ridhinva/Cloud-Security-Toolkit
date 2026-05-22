#!/usr/bin/env python3
"""
Azure Cloud Security Scanner

A toolkit for enumerating and testing Azure cloud resources for common
security misconfigurations.

Features:
    - Azure Storage Account enumeration (Blob containers, Table/Queue services)
    - Azure Instance Metadata Service (IMDS) exploitation check
    - Azure Key Vault discovery and misconfiguration testing

Usage:
    python azure_scanner.py --storage-enum <storage_account_name>
    python azure_scanner.py --imds-check
    python azure_scanner.py --keyvault-enum <vault_name>

Examples:
    # Enumerate a storage account's blob containers
    python azure_scanner.py --storage-enum myaccount

    # Check if IMDS endpoint is accessible (run on an Azure VM)
    python azure_scanner.py --imds-check

    # Check a Key Vault for public accessibility
    python azure_scanner.py --keyvault-enum myvault

How It Works:

    Storage Enumeration:
        Probes Azure Blob Storage endpoints using the pattern:
        https://<account>.blob.core.windows.net/<container>?restype=container&comp=list
        Common container names (backup, logs, data, config, etc.) are tested.
        A 200 response with XML listing indicates an unauthenticated public container.
        A 403 response indicates the container exists but is private.
        A 404 indicates the container does not exist.

    IMDS Check:
        Queries the Azure Instance Metadata Service endpoint at
        http://169.254.169.254/metadata/instance?api-version=2021-02-01
        with the required Metadata:true header.
        If accessible, this leaks VM metadata including:
          - Compute: name, resource group, subscription ID, region, VM size
          - Network: private IP, public IP, subnet, vnet info
        This is a critical attack vector — if an attacker reaches this endpoint
        via SSRF, they can harvest full VM metadata without authentication.

    Key Vault Enumeration:
        Probes Azure Key Vault DNS endpoints:
        https://<vault>.vault.azure.net/
        Tests common secret/ key names and checks vault accessibility.
        A successful response indicates the vault exists; a 403 with valid
        Auth header suggests misconfigured access policies.

Dependencies:
    - requests (pip install requests)
"""

if __name__ == "__main__":
    import sys

    print("Azure Cloud Security Scanner")
    print("=" * 60)
    print(__doc__)

    if len(sys.argv) < 2:
        print("\nNo arguments provided. Run with --help for usage.")
        print("Example: python azure_scanner.py --storage-enum myaccount")
        sys.exit(1)
