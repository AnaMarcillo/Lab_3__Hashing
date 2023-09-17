import passlib.hash
salt = "PkWj6gM4"
passwords = ["changeme", "123456", "password"]
for password in passwords:
    hashed_password = passlib.hash.apr_md5_crypt.hash(password, salt=salt)    
    chars = hashed_password    
    print(f"Password: {password}")
    print(f"APR1 Hash : {chars}")
    print()


"""
Password: changeme
APR1 Hash : $apr1$PkWj6gM4$V2w1yci/N1HCLzcqo3jiZ/

Password: 123456
APR1 Hash : $apr1$PkWj6gM4$opHu7xKPBmSPWdVO8vidC/

Password: password
APR1 Hash : $apr1$PkWj6gM4$OupRScHgsxe5lQj4.azPy.
"""
