from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
from os import urandom

# Generate Bob's RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

with open("public.pem", "wb") as f:
    f.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo))
with open("private.pem", "wb") as f:
    f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PrivateFormat.TraditionalOpenSSL,
                                      encryption_algorithm=serialization.NoEncryption()))

# Alice creates a message
plaintext = b"This is Alice's secret file for Bob."
with open("alice_message.txt", "wb") as f:
    f.write(plaintext)

# Generate AES-256 key and IV
aes_key = urandom(32)
iv = urandom(16)

# Encrypt file using AES-256 CBC
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
pad_len = 16 - (len(plaintext) % 16)
padded_plaintext = plaintext + bytes([pad_len] * pad_len)
encrypted = encryptor.update(padded_plaintext) + encryptor.finalize()
with open("encrypted_file.bin", "wb") as f:
    f.write(iv + encrypted)

# Encrypt AES key using Bob's RSA public key
encrypted_aes_key = public_key.encrypt(
    aes_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                 algorithm=hashes.SHA256(), label=None)
)
with open("aes_key_encrypted.bin", "wb") as f:
    f.write(encrypted_aes_key)

# Bob decrypts AES key
decrypted_aes_key = private_key.decrypt(
    encrypted_aes_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                 algorithm=hashes.SHA256(), label=None)
)

# Bob decrypts the file
with open("encrypted_file.bin", "rb") as f:
    iv2 = f.read(16)
    encrypted_data = f.read()
cipher2 = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv2), backend=default_backend())
decryptor = cipher2.decryptor()
decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
unpad_len = decrypted_padded[-1]
decrypted = decrypted_padded[:-unpad_len]
with open("decrypted_message.txt", "wb") as f:
    f.write(decrypted)

# Integrity Check
original_hash = hashlib.sha256(plaintext).hexdigest()
final_hash = hashlib.sha256(decrypted).hexdigest()
print("SHA-256 integrity check:", "PASS" if original_hash == final_hash else "FAIL")
