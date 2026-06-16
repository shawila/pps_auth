#!/usr/bin/env python3
"""Convert public.pem to jwks.json. Requires: pip install cryptography"""
import base64
import json
import sys
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

def b64url(n: int) -> str:
    byte_length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(byte_length, "big")).rstrip(b"=").decode()

pub_path = sys.argv[1] if len(sys.argv) > 1 else "public.pem"
out_path = sys.argv[2] if len(sys.argv) > 2 else "jwks.json"

with open(pub_path, "rb") as f:
    key = load_pem_public_key(f.read())

assert isinstance(key, RSAPublicKey), "Expected RSA public key"
nums = key.public_numbers()

jwks = {
    "keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "1",
        "n": b64url(nums.n),
        "e": b64url(nums.e),
    }]
}

with open(out_path, "w") as f:
    json.dump(jwks, f, indent=2)

print(f"Written {out_path}")
