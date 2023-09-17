import sys
from hashlib import md5
import passlib.hash
import bcrypt
import hashlib

num = 30
repeat_n = 1

salt = "ZDzPE45C"
string = "hello"
salt2 = "1111111111111111111111"
print("Word: ", string)
print("Salt: ", salt)

print("\nHashes")
print("SHA-1: \t", hashlib.sha1(string.encode()).hexdigest())
print("SHA-256: \t", hashlib.sha256(string.encode()).hexdigest())
print("SHA-512: \t", hashlib.sha512(string.encode()).hexdigest())

print("MD-5:\t\t\t", md5(string.encode()).hexdigest())
print("DES:\t\t\t", passlib.hash.des_crypt.hash(string.encode(), salt=salt[:2]))

print("Bcrypt:\t\t\t", bcrypt.kdf(string.encode(), salt=salt.encode(), desired_key_bytes=32, rounds=100).hex())

print("APR1:\t\t\t", passlib.hash.apr_md5_crypt.hash(string.encode(), salt=salt))

print("PBKDF2 (SHA1):\t\t", passlib.hash.pbkdf2_sha1.hash(string.encode(), rounds=5, salt=salt.encode()))
print("PBKDF2 (SHA-256):\t", passlib.hash.pbkdf2_sha256.hash(string, rounds=5, salt=salt.encode()))
