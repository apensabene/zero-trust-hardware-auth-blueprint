"""
FIDO2 / WebAuthn Enrollment Posture Auditor for Okta Identity Engine.

Authenticates via OAuth 2.0 client_credentials using private_key_jwt (RS256)
with least-privilege scope (okta.users.read) to audit active users and identify
accounts lacking phishing-resistant FIDO2/WebAuthn authenticators.

Required Env Vars:
  OKTA_ORG_URL          e.g., https://dev-000000.oktapreview.com
  OKTA_CLIENT_ID        Client ID of the Okta API Services OIDC app
  OKTA_PRIVATE_KEY_FILE Path to RS256 private key (.pem or .jwk)
  OKTA_KEY_ID           (Optional) Key ID (kid) header if multiple keys exist
"""
import os
import sys
import time
import uuid
import json
import jwt
import requests

REQUIRED_VARS = ("OKTA_ORG_URL", "OKTA_CLIENT_ID", "OKTA_PRIVATE_KEY_FILE")
missing = [v for v in REQUIRED_VARS if not os.environ.get(v)]
if missing:
    sys.exit(f"Missing required environment variable(s): {', '.join(missing)}")

ORG_URL = os.environ["OKTA_ORG_URL"].rstrip("/")
CLIENT_ID = os.environ["OKTA_CLIENT_ID"]
TOKEN_URL = f"{ORG_URL}/oauth2/v1/token"
SCOPES = os.environ.get("OKTA_SCOPES", "okta.users.read")

_token_cache = {"value": None, "expires_at": 0}


def _load_private_key():
    with open(os.environ["OKTA_PRIVATE_KEY_FILE"], "r", encoding="utf-8") as fh:
        raw = fh.read().strip()
    return jwt.algorithms.RSAAlgorithm.from_jwk(raw) if raw.startswith("{") else raw


def get_access_token() -> str:
    """Mint a short-lived OAuth 2.0 access token via RS256 private_key_jwt assertion."""
    if _token_cache["value"] and time.time() < _token_cache["expires_at"] - 60:
        return _token_cache["value"]

    now = int(time.time())
    kid = os.environ.get("OKTA_KEY_ID")
    assertion = jwt.encode(
        {
            "iss": CLIENT_ID,
            "sub": CLIENT_ID,
            "aud": TOKEN_URL,
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
        },
        _load_private_key(),
        algorithm="RS256",
        headers={"kid": kid} if kid else None,
    )

    resp = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "scope": SCOPES,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
        },
        headers={"Accept": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    payload = resp.json()
    _token_cache["value"] = payload["access_token"]
    _token_cache["expires_at"] = time.time() + int(payload.get("expires_in", 3600))
    return _token_cache["value"]


def auth_headers() -> dict:
    return {"Authorization": f"Bearer {get_access_token()}", "Accept": "application/json"}


def iter_active_users(limit: int = 200):
    """Yield ACTIVE Okta users following Link: rel='next' pagination."""
    url = f"{ORG_URL}/api/v1/users"
    params = {"filter": 'status eq "ACTIVE"', "limit": limit}
    while url:
        resp = requests.get(url, headers=auth_headers(), params=params, timeout=30)
        resp.raise_for_status()
        yield from resp.json()
        params = None
        url = (resp.links.get("next") or {}).get("url")


def audit_fido2_posture():
    total_active = 0
    fido2_enrolled = 0
    gaps = []

    for user in iter_active_users():
        total_active += 1
        uid = user["id"]
        login = (user.get("profile") or {}).get("login", uid)

        resp = requests.get(f"{ORG_URL}/api/v1/users/{uid}/factors", headers=auth_headers(), timeout=30)
        resp.raise_for_status()
        active_factors = [
            f.get("factorType")
            for f in resp.json()
            if f.get("status") == "ACTIVE"
        ]

        if "webauthn" in active_factors:
            fido2_enrolled += 1
        else:
            gaps.append({"user_id": uid, "login": login, "enrolled_factors": active_factors})

    coverage = (fido2_enrolled / total_active * 100) if total_active else 0.0
    report = {
        "active_users_audited": total_active,
        "fido2_webauthn_enrolled": fido2_enrolled,
        "phishing_resistant_coverage_pct": round(coverage, 2),
        "users_missing_fido2_count": len(gaps),
        "users_missing_fido2": gaps,
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    audit_fido2_posture()