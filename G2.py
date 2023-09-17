import argon2
from getpass import getpass
argon2_hasher = argon2.PasswordHasher()
def hash_password(password):
    return argon2_hasher.hash(password)

def verify_password(hashed_password, input_password):
    try:
        argon2_hasher.verify(hashed_password, input_password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False

if __name__ == "__main__":
    print("Argon2 Password Hashing Example")

    password = getpass("Enter a password: ")
    hashed_password = hash_password(password)
    print(f"Hashed Password: {hashed_password}")
    input_password = getpass("Enter the password to verify: ")
    if verify_password(hashed_password, input_password):
        print("Password Verified: Match")
    else:
        print("Password Verification Failed: Mismatch")
