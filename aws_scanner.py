#!/usr/bin/env python3
"""
AWS Security Scanner - S3 Bucket Enumeration Tool

Scans AWS S3 buckets for public access or existence using bucket name
permutations and domain-based enumeration. Multi-threaded for speed.

Usage:
    python aws_scanner.py --s3-brute <base_name>
    python aws_scanner.py --enum <domain>

Examples:
    python aws_scanner.py --s3-brute mycompany
    python aws_scanner.py --enum example.com
"""

import argparse
import concurrent.futures
import sys
import time

import requests

# Common S3 bucket name suffixes to probe
BUCKET_SUFFIXES = [
    "test", "dev", "prod", "backup", "logs", "data",
    "uploads", "files", "static", "public", "private",
    "temp", "config", "images", "media", "assets",
]

# Default AWS S3 bucket URL template
S3_URL_TEMPLATE = "https://{bucket}.s3.amazonaws.com"


def probe_bucket(bucket_name: str) -> dict:
    """
    Probe a single S3 bucket to check if it exists and is publicly accessible.

    Args:
        bucket_name: The full S3 bucket name to check.

    Returns:
        dict with keys: bucket, status_code, accessible, exists
    """
    url = S3_URL_TEMPLATE.format(bucket=bucket_name)
    result = {
        "bucket": bucket_name,
        "url": url,
        "status_code": None,
        "accessible": False,
        "exists": False,
    }

    try:
        resp = requests.get(url, timeout=10, allow_redirects=False)

        result["status_code"] = resp.status_code

        if resp.status_code == 200:
            # Bucket exists and is publicly listable/readable
            result["accessible"] = True
            result["exists"] = True
        elif resp.status_code == 403:
            # Bucket exists but access is denied (403 Forbidden)
            result["exists"] = True
        elif resp.status_code == 404:
            # Bucket does not exist
            pass
        elif resp.status_code == 301:
            # Redirect typically means bucket exists in a different region
            result["exists"] = True
            result["accessible"] = True
        else:
            # Other status codes
            result["exists"] = resp.status_code != 404

    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.RequestException:
        pass

    return result


def s3_bruteforce(base_name: str, max_workers: int = 20) -> list:
    """
    Probe common S3 bucket name variations based on a base name.

    Generates names like: base-test, base-dev, base-prod, ...

    Args:
        base_name: The base name (e.g. company name)
        max_workers: Number of concurrent threads

    Returns:
        list of probe results
    """
    bucket_names = [f"{base_name}-{suffix}" for suffix in BUCKET_SUFFIXES]
    results = []

    print(f"[*] Probing {len(bucket_names)} bucket names for base: {base_name}")
    print(f"[*] Using {max_workers} worker threads\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_bucket = {
            executor.submit(probe_bucket, name): name for name in bucket_names
        }

        completed = 0
        for future in concurrent.futures.as_completed(future_to_bucket):
            completed += 1
            bucket_name = future_to_bucket[future]
            try:
                result = future.result()
                results.append(result)

                if result["exists"]:
                    status = "PUBLIC" if result["accessible"] else "EXISTS (403)"
                    print(f"  [+] {result['url']:60s} [{status}]")
                else:
                    print(f"  [-] {result['url']:60s} [NOT FOUND]")

                if completed % 5 == 0:
                    print(f"  [*] Progress: {completed}/{len(bucket_names)} buckets checked\n")

            except Exception as e:
                print(f"  [!] Error probing {bucket_name}: {e}")

    return results


def enum_domain(domain: str, max_workers: int = 20) -> list:
    """
    Probe domain-based S3 bucket names.

    Tries both <domain> and <sanitized_domain> as bucket names.

    Args:
        domain: The target domain (e.g. example.com)
        max_workers: Number of concurrent threads

    Returns:
        list of probe results
    """
    sanitized = domain.replace(".", "-").lower()
    bucket_names = [sanitized, domain.lower()]
    results = []

    print(f"[*] Probing domain-based S3 bucket names for: {domain}")
    print(f"[*] Checking: {sanitized}, {domain.lower()}\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_bucket = {
            executor.submit(probe_bucket, name): name for name in bucket_names
        }

        for future in concurrent.futures.as_completed(future_to_bucket):
            bucket_name = future_to_bucket[future]
            try:
                result = future.result()
                results.append(result)

                if result["exists"]:
                    status = "PUBLIC" if result["accessible"] else "EXISTS (403)"
                    print(f"  [+] {result['url']:60s} [{status}]")
                else:
                    print(f"  [-] {result['url']:60s} [NOT FOUND]")

            except Exception as e:
                print(f"  [!] Error probing {bucket_name}: {e}")

    return results


def print_summary(results: list) -> None:
    """Print a summary of findings."""
    public = [r for r in results if r["accessible"]]
    exists_but_private = [r for r in results if r["exists"] and not r["accessible"]]
    not_found = [r for r in results if not r["exists"]]

    print("\n" + "=" * 70)
    print("SCAN SUMMARY")
    print("=" * 70)
    print(f"  Total buckets probed:  {len(results)}")
    print(f"  Publicly accessible:   {len(public)}")
    print(f"  Exists (private):      {len(exists_but_private)}")
    print(f"  Not found:             {len(not_found)}")

    if public:
        print("\n[!] PUBLICLY ACCESSIBLE BUCKETS (High Risk):")
        for r in public:
            print(f"     {r['url']}")

    if exists_but_private:
        print("\n[*] EXISTING BUT PRIVATE BUCKETS (Potential Target):")
        for r in exists_but_private:
            print(f"     {r['url']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AWS S3 Bucket Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--s3-brute",
        metavar="BASE_NAME",
        help="Brute-force common S3 bucket names using a base name (e.g. company name)",
    )
    parser.add_argument(
        "--enum",
        metavar="DOMAIN",
        help="Enumerate S3 bucket names derived from a domain name",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Number of worker threads (default: 20)",
    )

    args = parser.parse_args()

    if not args.s3_brute and not args.enum:
        parser.print_help()
        sys.exit(1)

    start_time = time.time()

    if args.s3_brute:
        results = s3_bruteforce(args.s3_brute, args.workers)
    else:
        results = enum_domain(args.enum, args.workers)

    elapsed = time.time() - start_time
    print(f"\n[*] Scan completed in {elapsed:.2f} seconds")

    print_summary(results)


if __name__ == "__main__":
    main()
