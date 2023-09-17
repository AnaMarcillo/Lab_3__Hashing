import passlib.hash

salt = "8sFt66rZ"
passwords = ["changeme", "123456", "password"]

for password in passwords:
    sha1_hash = passlib.hash.sha1_crypt.hash(password, salt=salt)
    sha256_hash = passlib.hash.sha256_crypt.hash(password, salt=salt)
    sha512_hash = passlib.hash.sha512_crypt.hash(password, salt=salt)

    print(f"Password: {password}")
    print(f"SHA1: {sha1_hash}")
    print(f"SHA256: {sha256_hash}")
    print(f"SHA512: {sha512_hash}")
    print()

"""
Password: changeme
SHA1: $sha1$480000$8sFt66rZ$dNfLzeD4O48TgFqDKd0zBYc4SJ5a
SHA256: $5$rounds=535000$8sFt66rZ$yNCVBp7NMi3UNzMEIoGoGnQZ.HMGaUETwiQNCBi/cl5
SHA512: $6$rounds=656000$8sFt66rZ$B/.Msj2UuS3qH.Qxsy.RL82oni6MV75LZ8olN6eCw6.LSHCCcJ4IGnzdX9Qv299whMbpz4rR9e7A9Ab0L3ZA0/

Password: 123456
SHA1: $sha1$480000$8sFt66rZ$RndE8VtL.VnDBVLPgp7vKcVb0BaN
SHA256: $5$rounds=535000$8sFt66rZ$rAkO4NCQq4l0DjDAJFh2f6s9Ew.Y7qCIM7okpuHJR30
SHA512: $6$rounds=656000$8sFt66rZ$cGaBfax5eeGRKwD.bFK0IFUvrk0jyyeWKIkIsmWX0H9xvJco6OwFPZ5QA4jh5mZnt1w9FlhO2pKlhkpPHICts0

Password: password
SHA1: $sha1$480000$8sFt66rZ$h0Q07GoRgcYjKiYsjpufby/P7cf0
SHA256: $5$rounds=535000$8sFt66rZ$63AbYmdfWxNIp9x75xK4zBgdQxvzMGtNzpyI6DKhvb7
SHA512: $6$rounds=656000$8sFt66rZ$hiU32dGMdhmg9uxrHHBnVz1j5A35Ap193q.Naf9kUkP.e1klwhfPW3Lv/LIydTiS97Adp5zYGN.1RM8s6NcNy/
"""
