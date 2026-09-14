import base64
import json

import requests
from eth_account import Account
from eth_account.messages import encode_defunct

BASE = "https://app.nabu.pro/api/backend"

# Exported private key of the Privy embedded wallet.
PRIVKEY = "ba4c5c..."
PRIVY_SUB = "usr_2b8148b5d0c98844a3565d542ea0fc7d"

account = Account.from_key(PRIVKEY)
print("address:", account.address)

challenge = requests.post(
    f"{BASE}/v1/auth/challenge", json={"address": account.address}
).json()
print("challenge_id:", challenge["challenge_id"])

signed = account.sign_message(encode_defunct(text=challenge["message_to_sign"]))
verify = requests.post(
    f"{BASE}/v1/auth/verify",
    json={
        "challenge_id": challenge["challenge_id"],
        "address": account.address,
        "signature": signed.signature.hex(),
    },
).json()
token = verify["token"]

payload = token.split(".")[1]
payload += "=" * (-len(payload) % 4)
sub = json.loads(base64.urlsafe_b64decode(payload))["sub"]

headers = {"authorization": f"Bearer {token}"}
for path in ["/v1/trading-wallet?chain_id=1", "/v1/invite/status", "/v1/chats"]:
    r = requests.get(f"{BASE}{path}", headers=headers)
    print(f"\nGET {path} -> {r.status_code}")
    print(r.text)
