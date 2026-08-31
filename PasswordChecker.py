import math
import hashlib
import getpass
import requests
import argparse
from typing import Tuple

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

def calculate_shannon_entropy(password: str) -> float:
    """Calculates NIST-style character pool entropy."""
    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(not c.isalnum() for c in password):
        pool_size += 32  # Common ASCII punctuation

    if pool_size == 0 or len(password) == 0:
        return 0.0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)

def check_hibp_pwned(password: str) -> int:
    """
    Queries HIBP using k-Anonymity.
    Never sends full hash or plaintext password over the wire.
    """
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        response = requests.get(
            f"{HIBP_API_URL}{prefix}",
            headers={"User-Agent": "UniBrighton-Student-Security-Auditor"},
            timeout=5.0
        )
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] Warning: Breach database unreachable ({e}).")
        return -1

    # Format of response: SUFFIX:COUNT
    hashes = (line.split(":") for line in response.text.splitlines())
    for remote_suffix, count in hashes:
        if remote_suffix == suffix:
            return int(count)
    return 0

def audit_password(password: str) -> Tuple[bool, list]:
    findings = []
    
    # 1. Structural Checks
    if len(password) < 12:
        findings.append("Length is under NIST-recommended 12 characters.")
    if not any(c.isupper() for c in password):
        findings.append("Missing uppercase characters.")
    if not any(c.islower() for c in password):
        findings.append("Missing lowercase characters.")
    if not any(c.isdigit() for c in password):
        findings.append("Missing numeric digits.")
    if not any(not c.isalnum() for c in password):
        findings.append("Missing special symbols.")

    # 2. Information Density
    entropy = calculate_shannon_entropy(password)
    if entropy < 60:
        findings.append(f"Low entropy: {entropy} bits (Aim for >= 60 bits).")

    # 3. Breach Intelligence
    pwn_count = check_hibp_pwned(password)
    if pwn_count > 0:
        findings.append(f"CRITICAL: Found in public breaches ({pwn_count:,} times via HIBP).")

    is_strong = len(findings) == 0
    return is_strong, findings

def main():
    parser = argparse.ArgumentParser(description="Cryptographic Password Complexity & Breach Auditor")
    parser.add_argument("--audit-only", action="store_true", help="Run in automated CI/CD mode")
    args = parser.parse_args()

    # Use getpass to prevent shoulder surfing
    password = getpass.getpass("Enter password to audit (masked): ")
    if not password:
        print("Empty string provided.")
        return

    is_strong, issues = audit_password(password)
    
    print("\n--- Audit Report ---")
    if is_strong:
        print("[+] PASS: Password meets entropy baselines and zero breach presence.")
    else:
        print("[-] FAIL: Weaknesses identified:")
        for issue in issues:
            print(f"  * {issue}")

if __name__ == "__main__":
    main()