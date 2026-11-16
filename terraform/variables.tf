variable "okta_org_name" {
  description = "Okta subdomain (e.g., 'dev-123456' for dev-123456.okta.com)"
  type        = string
}

variable "okta_base_url" {
  description = "Okta base domain ('okta.com', 'oktapreview.com', or 'okta-emea.com')"
  type        = string
  default     = "okta.com"
}

variable "reauth_frequency" {
  description = "ISO-8601 duration before requiring fresh FIDO2 user verification (default: 2 hours)"
  type        = string
  default     = "PT2H"
}