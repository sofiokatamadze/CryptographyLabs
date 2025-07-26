# Task 1: Encrypted Messaging App (RSA + AES)

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom

# User A generates RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# User B writes a secret message
message = b"This is a secret message from User B."
with open("message.txt", "wb") as f:
    f.write(message)

# AES encryption with random key
aes_key = urandom(32)
iv = urandom(16)
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
padded_message = message + b' ' * (16 - len(message) % 16)
encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
with open("encrypted_message.bin", "wb") as f:
    f.write(iv + encrypted_message)

# Encrypt AES key with RSA public key
encrypted_aes_key = public_key.encrypt(
    aes_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
with open("aes_key_encrypted.bin", "wb") as f:
    f.write(encrypted_aes_key)

# User A decrypts the AES key
decrypted_aes_key = private_key.decrypt(
    encrypted_aes_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

# Decrypt the message
cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
decrypted_message = decrypted_message.rstrip(b' ')
with open("decrypted_message.txt", "wb") as f:
    f.write(decrypted_message)