# Security Policy

## Supported Versions

Only the latest state of the `main` branch is actively maintained and supported with security updates.

| Branch / Version | Supported |
| ---------------- | --------- |
| `main`           | Yes       |
| Older commits    | No        |

## Reporting a Vulnerability

Please **do not** report security vulnerabilities, authentication policy bypasses, PKI validation flaws, or exposed private keys through public GitHub Issues or Pull Requests.

Instead, report vulnerabilities privately via one of the following channels:

1. **GitHub Private Vulnerability Reporting:** Use the **Report a vulnerability** button under the **Security** tab of `apensabene/zero-trust-hardware-auth-blueprint`.
2. **Direct Contact:** Email **apensabene@pm.me** with the subject line `[SECURITY] zero-trust-hardware-auth-blueprint - <Brief Summary>`.

### What to Include
* Description of the issue and affected file(s) (Terraform policy-as-code definitions, Python FIDO2 enrollment auditor, or OpenSSL S/MIME validation scripts)
* Potential impact (e.g., fallback to phishable MFA factors, weak AAL3 assurance enforcement, or invalid certificate chain acceptance)
* Steps to reproduce or suggested remediation

### Response Timeline
* **Initial Acknowledgment:** Within 48 hours
* **Triage & Remediation Assessment:** Within 5 business days

## Security Architecture & Baseline Controls

This repository enforces the following security practices:
* **Phishing-Resistant Assurance (NIST SP 800-63B AAL3):** Enforces hardware-bound FIDO2/WebAuthn authentication policies via Terraform policy-as-code.
* **Zero-Static-Secret Posture Auditing:** Authenticates the Python FIDO2 enrollment auditor via OAuth 2.0 `private_key_jwt` rather than static API keys.
* **Cryptographic & State Hygiene:** Validates S/MIME certificate Extended Key Usage (EKU) and trust chains while excluding private keys, certificates, and Terraform state files via `.gitignore`.
