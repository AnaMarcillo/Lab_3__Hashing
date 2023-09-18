from cryptography.hazmat.primitives import hashes, hmac
import binascii

def show_hash(hash_name, hash_algorithm, data, key):
    h = hmac.HMAC(key, hash_algorithm)
    h.update(data)
    result = h.finalize()
    hmac_hex = binascii.b2a_hex(result).decode()
    hmac_base64 = binascii.b2a_base64(result).decode()
    print(f"Data: {data.decode()}")
    print(f" Hex: {binascii.b2a_hex(data).decode()}")
    print(f"Key: {key.decode()}")
    print(f" Hex: {binascii.b2a_hex(key).decode()}")
    print(f"HMAC-{hash_name}: {hmac_hex} {hmac_base64}")

# Lista de datos, clave y tipo de hash
data_key_hash_list = ["Hello", "qwerty123", "SHA1"]

try:
    # Extraer los elementos de la lista
    data = data_key_hash_list[0].encode()
    key = data_key_hash_list[1].encode()
    hash_type = data_key_hash_list[2]

    print("Data:", data_key_hash_list[0])
    print(" Hex:", binascii.b2a_hex(data).decode())
    print("Key:", data_key_hash_list[1])
    print(" Hex:", binascii.b2a_hex(key).decode())
    print()
    if hash_type == "MD5":
        show_hash("MD5", hashes.MD5(), data, key)
    elif hash_type == "SHA1":
        show_hash("SHA-1", hashes.SHA1(), data, key)
    elif hash_type == "SHA224":
        show_hash("SHA-224", hashes.SHA224(), data, key)
    elif hash_type == "SHA256":
        show_hash("SHA-256", hashes.SHA256(), data, key)
    elif hash_type == "SHA512":
        show_hash("SHA-512", hashes.SHA512(), data, key)
    elif hash_type == "SM3":
        show_hash("SM3", hashes.SM3(), data, key)
    elif hash_type == "SHA3224":
        show_hash("SHA3-224", hashes.SHA3_224(), data, key)
    elif hash_type == "SHA3256":
        show_hash("SHA3-256", hashes.SHA3_256(), data, key)
    elif hash_type == "SHA3384":
        show_hash("SHA3-384", hashes.SHA3_384(), data, key)
    elif hash_type == "SHA3512":
        show_hash("SHA3-512", hashes.SHA3_512(), data, key)
    elif hash_type == "SHAKE128":
        show_hash("SHAKE128 (32 bytes)", hashes.SHAKE128(32), data, key)
    elif hash_type == "SHAKE256":
        show_hash("SHAKE256 (32 bytes)", hashes.SHAKE256(32), data, key)
    elif hash_type == "BLAKE2b":
        show_hash("BLAKE2b (32 bytes)", hashes.BLAKE2b(32), data, key)
    elif hash_type == "BLAKE2s":
        show_hash("BLAKE2s (32 bytes)", hashes.BLAKE2s(32), data, key)
    else:
        print("Unsupported hash algorithm:", hash_type)

except Exception as e:
    print(e)

