import subprocess
import os

# 1. Create original text file
with open("message.txt", "w") as file:
    file.write("This is a secret message for Applied Cryptography Lab.\n")

# 2. Generate RSA Key Pair (private.pem, public.pem)
subprocess.run(["openssl", "genrsa", "-out", "private.pem", "2048"])
subprocess.run(["openssl", "rsa", "-in", "private.pem", "-pubout", "-out", "public.pem"])

# 3. Encrypt the file using RSA public key
subprocess.run(["openssl", "rsautl", "-encrypt", "-pubin", "-inkey", "public.pem",
                "-in", "message.txt", "-out", "message_rsa_encrypted.bin"])

# 4. Decrypt the RSA encrypted file using private key
subprocess.run(["openssl", "rsautl", "-decrypt", "-inkey", "private.pem",
                "-in", "message_rsa_encrypted.bin", "-out", "message_rsa_decrypted.txt"])

# 5. Generate AES-256 key and IV
subprocess.run(["openssl", "rand", "-out", "aes_key.bin", "32"])  # 256 bits = 32 bytes
subprocess.run(["openssl", "rand", "-out", "aes_iv.bin", "16"])   # IV = 16 bytes for AES

# 6. Encrypt the file using AES-256
subprocess.run(["openssl", "enc", "-aes-256-cbc", "-in", "message.txt",
                "-out", "message_aes_encrypted.bin",
                "-K", open("aes_key.bin", "rb").read().hex(),
                "-iv", open("aes_iv.bin", "rb").read().hex()])

# 7. Decrypt the AES encrypted file
subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc",
                "-in", "message_aes_encrypted.bin",
                "-out", "message_aes_decrypted.txt",
                "-K", open("aes_key.bin", "rb").read().hex(),
                "-iv", open("aes_iv.bin", "rb").read().hex()])

# 8. Explanation of RSA vs AES (performance and use-cases)
explanation = """
RSA vs AES Encryption

Performance:
- RSA encryption/decryption is significantly slower due to complex mathematical operations involving large prime number factorization.
- AES is optimized for speed and efficiency, making it suitable for encrypting large files or streaming data.

Use-cases:
- RSA is commonly used for encrypting small data (like symmetric keys or passwords), digital signatures, and key exchanges.
- AES is ideal for bulk encryption of files, database contents, messages, and general data at rest or in transit.

Common Practice:
- Combine RSA (for secure key exchange) and AES (for actual bulk encryption).
"""

with open("rsa_vs_aes.txt", "w") as file:
    file.write(explanation.strip())

print("All encryption/decryption operations completed successfully.")
