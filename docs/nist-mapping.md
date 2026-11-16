# NIST & Zero Trust Control Mapping

This blueprint maps phishing-resistant hardware authentication (FIDO2/WebAuthn) and cryptographic message security (S/MIME) to **NIST SP 800-63B**, **NIST SP 800-53 Rev. 5**, and **NIST SP 800-207 (Zero Trust Architecture)**.

| Control Objective | Blueprint Implementation | NIST SP 800-63B | NIST SP 800-53 Rev. 5 | Zero Trust Principle |
| :--- | :--- | :--- | :--- | :--- |
| **Phishing-Resistant Authentication** | Okta Identity Engine (OIE) WebAuthn policy enforcing `phishingResistant = REQUIRED` and origin-bound assertions | **AAL3** (Section 4.3.1 / 5.1.9) | **IA-2(6)** (Network Access to Privileged Accounts — Replay-Resistant) | Never trust, always verify; eliminate replayable credentials |
| **Hardware Key Binding (Block Synced Passkeys)** | Device-bound cryptographic authenticator constraint (`deviceBound = REQUIRED`) + AAGUID allowlisting | **AAL3** (Hardware Cryptographic Authenticator) | **IA-2(12)** (Acceptance of PIV / Hardware Credentials) | Strong cryptographic device identity |
| **Multi-Factor User Verification** | Mandatory CTAP2 PIN or biometric check (`userVerification = REQUIRED`) + physical touch (`userPresence`) | **AAL3** (Two distinct authentication factors) | **IA-2(1)** / **IA-2(2)** | Explicit verification of both user presence and possession |
| **Session Re-Authentication** | Bounded high-assurance session lifetime (`PT2H`) on sensitive applications | **AAL3** Reauthentication (Section 4.3.3) | **AC-11** / **AC-12** (Session Lock & Termination) | Least-privilege, time-bound session grants |
| **Cryptographic Email Signing & Encryption** | S/MIME X.509 certificates stored on hardware tokens (`emailProtection` EKU) for CMS/PKCS#7 signing | N/A (Message-layer assurance) | **SC-12** (Cryptographic Key Management) & **SC-13** (Cryptographic Protection) | End-to-end data integrity and non-repudiation |
| **Automated Posture & Hygiene Auditing** | `audit_fido2_enrollments.py` (least-privilege `private_key_jwt` API audit) & `verify_smime_cert.sh` | Continuous Monitoring | **AU-2** / **CA-7** (Continuous Monitoring) | Continuous diagnostics and mitigation |