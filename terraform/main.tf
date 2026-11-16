terraform {
  required_version = ">= 1.5.0"

  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 4.9"
    }
  }
}

provider "okta" {
  org_name = var.okta_org_name
  base_url = var.okta_base_url
}

# 1. Enable FIDO2 (WebAuthn) Authenticator with mandatory User Verification (PIN / Biometric)
resource "okta_authenticator" "fido2_webauthn" {
  name   = "FIDO2 (WebAuthn)"
  key    = "webauthn"
  status = "ACTIVE"

  settings = jsonencode({
    userVerification = "REQUIRED"
  })
}

# 2. High-Assurance App Sign-On Policy (Zero Trust / AAL3 Baseline)
resource "okta_app_signon_policy" "zero_trust_hardware" {
  name        = "Zero-Trust-Hardware-FIDO2-Policy"
  description = "Enforces device-bound, phishing-resistant FIDO2/WebAuthn hardware keys with user verification."
}

# 3. Policy Rule requiring Device-Bound + Phishing-Resistant Possession
resource "okta_app_signon_policy_rule" "require_hardware_fido2" {
  policy_id                   = okta_app_signon_policy.zero_trust_hardware.id
  name                        = "Require Device-Bound Phishing-Resistant MFA"
  priority                    = 1
  factor_mode                 = "2FA"
  re_authentication_frequency = var.reauth_frequency

  constraints = [
    jsonencode({
      possession = {
        deviceBound       = "REQUIRED"
        phishingResistant = "REQUIRED"
        userPresence      = "REQUIRED"
        userVerification  = "REQUIRED"
      }
    })
  ]

  depends_on = [okta_authenticator.fido2_webauthn]
}

output "zero_trust_policy_id" {
  description = "ID of the Zero Trust Hardware FIDO2 App Sign-On Policy"
  value       = okta_app_signon_policy.zero_trust_hardware.id
}