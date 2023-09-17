import passlib.hash

salt = "ZDzPE45C"
passwords = ["changeme", "123456", "password"]

for password in passwords:

    pbkdf2_sha1_hash = passlib.hash.pbkdf2_sha1.hash(password, salt=salt.encode())
    pbkdf2_sha1_chars = pbkdf2_sha1_hash

    pbkdf2_sha256_hash = passlib.hash.pbkdf2_sha256.hash(password, salt=salt.encode())
    pbkdf2_sha256_chars = pbkdf2_sha256_hash

    print(f"Password: {password}")
    print(f"PBKDF2 (SHA1): {pbkdf2_sha1_chars}")
    print(f"PBKDF2 (SHA256): {pbkdf2_sha256_chars}")
    print()
  
