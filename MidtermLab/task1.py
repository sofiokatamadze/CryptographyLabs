from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import MD5

# Step 1: Create the original plaintext file ===
plaintext_str = "This file contains top secret information."
with open("secret.txt", "w") as f:
    f.write(plaintext_str)


# Step 2: OpenSSL-compatible Key Derivation ===
def openssl_key_iv(passphrase: bytes, salt: bytes, key_len=16, iv_len=16):
    d = d_i = b""
    while len(d) < key_len + iv_len:
        d_i = MD5.new(d_i + passphrase + salt).digest()
        d += d_i
    return d[:key_len], d[key_len:key_len + iv_len]


# Step 3: Read the plaintext ===
with open("secret.txt", "rb") as f:
    plaintext = f.read()

# Step 4: AES-128-CBC Encryption with Passphrase ===
passphrase = b"MySecret123"
salt = get_random_bytes(8)
key, iv = openssl_key_iv(passphrase, salt)

# Pad plaintext (PKCS7)
pad_len = 16 - (len(plaintext) % 16)
plaintext_padded = plaintext + bytes([pad_len] * pad_len)

cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(plaintext_padded)

# Save encrypted file in OpenSSL format
with open("secret.enc", "wb") as f:
    f.write(b"Salted__" + salt + ciphertext)

print("Encrypted file saved as secret.enc")

# Step 5: AES-128-CBC Decryption ===
with open("secret.enc", "rb") as f:
    data = f.read()

assert data[:8] == b"Salted__", "Missing OpenSSL header"
salt = data[8:16]
ciphertext = data[16:]

key, iv = openssl_key_iv(passphrase, salt)
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext_decrypted_padded = cipher.decrypt(ciphertext)

# Remove PKCS7 padding
pad_len = plaintext_decrypted_padded[-1]
plaintext_decrypted = plaintext_decrypted_padded[:-pad_len]

# Save decrypted file
with open("decrypted_secret.txt", "wb") as f:
    f.write(plaintext_decrypted)

print("Decrypted file saved as decrypted_secret.txt")

# === Step 6: Verify ===
if plaintext_decrypted == plaintext:
    print("Success! Decrypted text matches original.")
else:
    print("Mismatch found between original and decrypted.")
