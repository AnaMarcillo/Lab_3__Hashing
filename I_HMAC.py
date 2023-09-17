import argparse
from cryptography.hazmat.primitives import hashes, hmac
import binascii

def show_hash(hash_name, hash_algorithm, data, key):
    h = hmac.HMAC(key, hash_algorithm)
    h.update(data)
    result = h.finalize()
    print(f"HMAC-{hash_name}: {binascii.b2a_hex(result).decode()} {binascii.b2a_base64(result).decode()}")

parser = argparse.ArgumentParser(description="Calculate HMAC hash for a given input and key.")
parser.add_argument("data", type=str, help="Input data")
parser.add_argument("key", type=str, help="HMAC key")
parser.add_argument("--hash", type=str, default="SHA256", help="Hash algorithm (default: SHA256)")


args = parser.parse_args()

try:

    data = args.data.encode()
    key = args.key.encode()

    print("Data:", args.data)
    print(" Hex:", binascii.b2a_hex(data).decode())
    print("Key:", args.key)
    print(" Hex:", binascii.b2a_hex(key).decode())
    print()
    if args.hash == "MD5":
        show_hash("MD5", hashes.MD5(), data, key)
    elif args.hash == "SHA1":
        show_hash("SHA-1", hashes.SHA1(), data, key)
    elif args.hash == "SHA224":
        show_hash("SHA-224", hashes.SHA224(), data, key)
    elif args.hash == "SHA256":
        show_hash("SHA-256", hashes.SHA256(), data, key)
    elif args.hash == "SHA512":
        show_hash("SHA-512", hashes.SHA512(), data, key)
    else:
        print("Unsupported hash algorithm:", args.hash)

except Exception as e:
    print(e)
