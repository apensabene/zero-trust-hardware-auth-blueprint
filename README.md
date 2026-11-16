# Zero-Trust Hardware Authentication & S/MIME Blueprint

Reference architecture, Terraform policy-as-code, and security auditing utilities for enforcing **phishing-resistant FIDO2/WebAuthn hardware authentication** (NIST SP 800-63B AAL3) alongside **S/MIME cryptographic email signing and encryption**.

---

## Architecture Overview

Modern Adversary-in-the-Middle (AiTM) reverse-proxy kits bypass legacy MFA (SMS, TOTP, and standard push notifications) by relaying session cookies in real time. Meanwhile, Business Email Compromise (BEC) exploits unauthenticated email transport. This blueprint addresses both attack surfaces:

1. **Identity & Session Layer (FIDO2 / WebAuthn):** Enforces origin-bound, device-bound hardware authenticators (deviceBound = REQUIRED, phishingResistant = REQUIRED) via Okta Identity Engine (OIE), blocking cloud-synced passkeys and phishable factors on high-assurance applications.
2. **Message & Document Layer (S/MIME):** Uses hardware-backed X.509 certificates (emailProtection EKU) for detached CMS/PKCS#7 digital signatures and message encryption.

mermaid
sequenceDiagram
    autonumber
    actor User as Enterprise User (Hardware Key)
    participant Client as Browser / Mail Client
    participant IdP as Okta Identity Engine (OIE)
    participant PKI as CA / OCSP Responder

    Note over User,IdP: Track 1: Phishing-Resistant Hardware Auth (AAL3)
    User->>Client: Initiates SSO / Sensitive App Access
    Client->>IdP: OIDC / SAML AuthN Request
    IdP-->>Client: WebAuthn Challenge (Device-Bound + UV Required)
    Client->>User: CTAP2 PIN / Biometric + Physical Touch
    User-->>Client: Origin-Bound Signed Assertion
    Client->>IdP: Submit Assertion
    IdP-->>Client: Scoped Session Token (PT2H Re-Auth)

    Note over User,PKI: Track 2: S/MIME Cryptographic Signing & Verification
    User->>Client: Signs Outgoing Message / Document
    Client->>User: Hardware Private Key Operation (PIN)
    User-->>Client: Detached PKCS#7 Signature
    Client->>PKI: Recipient Verifies Chain & Revocation Status


---

## Repository Structure

zero-trust-hardware-auth-blueprint/
├── docs/
│   └── nist-mapping.md                # NIST SP 800-63B, SP 800-53, and Zero Trust mapping
├── terraform/
│   ├── main.tf                        # Okta WebAuthn authenticator & AAL3 sign-on policy
│   ├── variables.tf                   # Input variable definitions
│   └── terraform.tfvars.example       # Sanitized example configuration
├── scripts/
│   ├── audit_fido2_enrollments.py     # OAuth 2.0 private_key_jwt FIDO2 posture auditor
│   ├── verify_smime_cert.sh           # OpenSSL S/MIME EKU, validity & chain checker
│   └── requirements.txt               # Python dependencies
└── .gitignore


## Quickstart

### 1. Provision Zero-Trust FIDO2 Policy (Terraform)
bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Populate okta_org_name in terraform.tfvars and set OKTA_API_TOKEN / OAuth credentials
terraform init
terraform plan


### 2. Audit FIDO2 Enrollment Coverage (Python + private_key_jwt)
Authenticates using an Okta API Services OIDC app with an RS256 keypair and least-privilege okta.users.read scope (no static SSWS tokens):

bash
cd scripts
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export OKTA_ORG_URL="[https://dev-000000.oktapreview.com](https://dev-000000.oktapreview.com)"
export OKTA_CLIENT_ID="0oa..."
export OKTA_PRIVATE_KEY_FILE="/path/to/private_key.pem"

python audit_fido2_enrollments.py


### 3. Validate S/MIME Certificate Hygiene (OpenSSL)
bash
chmod +x scripts/verify_smime_cert.sh
./scripts/verify_smime_cert.sh path/to/public_smime_cert.pem path/to/ca_chain.pem


---

## Threat Model & Security Controls

| Threat Vector | Mitigating Control | Residual Risk / Operational Note |
| :--- | :--- | :--- |
| **AiTM Reverse-Proxy Phishing** | WebAuthn origin-bound cryptographic challenge (phishingResistant = REQUIRED) | Requires blocking fallback to phishable factors (SMS/OTP) in policy rules |
| **Passkey Export / Cloud Sync Drift** | deviceBound = REQUIRED enforces hardware-resident private keys | Requires spare hardware key enrollment for break-glass account recovery |
| **Email Spoofing & Payload Tampering** | S/MIME detached signatures with hardware-protected private keys | Recipients must trust the issuing CA chain and check OCSP/CRL status |
| **Static API Credential Leakage** | audit_fido2_enrollments.py uses short-lived RS256 private_key_jwt assertions | Private key .pem/.jwk files must remain outside version control (.gitignore) |

---

## Disclaimer
All configurations and scripts are sanitized reference templates intended for lab validation and architectural design. Test in an Okta preview/sandbox tenant before deploying to production.

---

## Author

**Anthony Pensabene, CISSP** — Identity Security Engineer & Okta Subject Matter Expert  
* **GitHub:** [github.com/apensabene](https://github.com/apensabene)
* **LinkedIn:** [linkedin.com/in/apensabene]