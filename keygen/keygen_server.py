from common.crypto_utils import generate_keys
import json

public_key, private_key = generate_keys()

data = {
    "public_key": public_key,
    "private_key": private_key
}

with open("server_keys.json", "w") as f:
    json.dump(data, f)

print("✅ Server keys generated!")