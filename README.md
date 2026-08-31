# Privacy-Preserving Credential Auditor

A Python command-line utility that evaluates credential strength against NIST SP 800-63B guidelines and checks for real-world breach exposure using the HaveIBeenPwned API.

## Features
**Zero-Knowledge API Queries:** Implements the HaveIBeenPwned $k$-Anonymity model via SHA-1 hashing to verify breaches without leaking full hashes or credentials across the wire.
**Information Entropy Scoring:** Calculates Shannon entropy ($H = L \cdot \log_2(R)$) to measure mathematical brute-force search space rather than naive character counting.
**Secure Input Handling:** Utilizes masked terminal inputs (`getpass`) to prevent credential leakage via shoulder surfing or shell history.

## Installation & Usage
```bash
pip install -r requirements.txt
python PasswordChecker.py