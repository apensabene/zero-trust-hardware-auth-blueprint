#!/usr/bin/env bash
# Validates an X.509 S/MIME public certificate for expiration, Key Usage,
# Extended Key Usage (emailProtection), and optional CA chain trust.
set -euo pipefail

CERT_FILE="${1:-}"
CA_BUNDLE="${2:-}"

if [[ -z "$CERT_FILE" || ! -f "$CERT_FILE" ]]; then
  echo "Usage: $0 <public_cert.pem> [ca_chain.pem]"
  exit 1
fi

echo "=== Subject, Issuer & Validity ==="
openssl x509 -in "$CERT_FILE" -noout -subject -issuer -dates -serial

echo -e "\n=== Key Usage & Extended Key Usage (Requires E-mail Protection) ==="
EXT_OUT=$(openssl x509 -in "$CERT_FILE" -noout -ext keyUsage,extendedKeyUsage,subjectAltName)
echo "$EXT_OUT"

if echo "$EXT_OUT" | grep -q "E-mail Protection"; then
  echo "[PASS] Extended Key Usage includes E-mail Protection (1.3.6.1.5.5.7.3.4)."
else
  echo "[FAIL] Missing E-mail Protection EKU — certificate is not valid for S/MIME."
  exit 1
fi

echo -e "\n=== Expiration Check (30-Day Window) ==="
if openssl x509 -in "$CERT_FILE" -noout -checkend 2592000; then
  echo "[PASS] Certificate is valid for more than 30 days."
else
  echo "[WARN] Certificate expires within 30 days or is already expired."
fi

if [[ -n "$CA_BUNDLE" && -f "$CA_BUNDLE" ]]; then
  echo -e "\n=== CA Trust Chain Verification ==="
  openssl verify -CAfile "$CA_BUNDLE" "$CERT_FILE"
fi