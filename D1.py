import passlib.hash
words = ["Napier", "Foxrot"] # List of words
for word in words:
    uppercase_word = word.upper()     # Convert the word to uppercase as LM and NTLM hashes are case-insensitive
    lm_hash = passlib.hash.lmhash.hash(uppercase_word)     # Generate and print the LM and NTLM hashes for the word
    nt_hash = passlib.hash.nthash.hash(uppercase_word)   
    print(f"Word: {word}")
    print(f"LM Hash: {lm_hash}")
    print(f"NTLM Hash: {nt_hash}")
    print()
""" 
Word: Napier
LM Hash: 12b9c54f6fe0ec80aad3b435b51404ee
NTLM Hash: d0b72d7d45c68cde9f8a2bef0b7f9451

Word: Foxrot
LM Hash: f660c87bce347579aad3b435b51404ee
NTLM Hash: 85b402f72c46d34901de59d9b049280d
"""
