import argparse
import json
from common.crypto_utils import generate_keys

parser = argparse.ArgumentParser()
parser.add_argument("--id", required=True)
args = parser.parse_args()

public_key, private_key = generate_keys()

data = {
    "id": args.id,
    "public_key": public_key,
    "private_key": private_key
}

filename = f"{args.id}_keys.json"

with open(filename, "w") as f:
    json.dump(data, f)

print(f"✅ Keys generated for {args.id}")