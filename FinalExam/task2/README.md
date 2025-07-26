# Task 2: Secure File Exchange Using RSA + AES

## Encryption/Decryption Flow

**Step 1:** Bob generates an RSA key pair (`public.pem`, `private.pem`).  
**Step 2:** Alice writes her secret message to `alice_message.txt`.  
**Step 3:** Alice generates a random AES-256 key and IV.  
**Step 4:** Alice encrypts the message with AES-256 (CBC) → `encrypted_file.bin` (IV prepended).  
**Step 5:** Alice encrypts the AES key with Bob’s RSA public key → `aes_key_encrypted.bin`.  
**Step 6:** Bob decrypts the AES key using his private RSA key.  
**Step 7:** Bob decrypts the file using the AES key and IV, recovering the original message (`decrypted_message.txt`).  
**Step 8:** Bob computes SHA-256 hashes for the original and decrypted file to confirm integrity.

## Files Produced

- `alice_message.txt`: Alice’s plaintext
- `encrypted_file.bin`: AES-encrypted file (IV + ciphertext)
- `aes_key_encrypted.bin`: AES key encrypted with RSA
- `decrypted_message.txt`: Decrypted output (should match Alice's message)
- `public.pem`, `private.pem`: Bob's RSA key pair

## AES vs. RSA: Speed, Use Case, Security

- **AES:**  
  - Fast, symmetric block cipher, ideal for large files and bulk data.  
  - Used for message/file encryption.  
- **RSA:**  
  - Slower, asymmetric, designed for secure key exchange, not for large files.  
  - Used for encrypting the AES key.  
- **Hybrid Model:**  
  - Combines efficiency (AES) with secure key transport (RSA).  
  - Standard approach in secure communications (e.g., TLS).

## Security Note

AES provides strong data encryption, and RSA ensures only Bob can decrypt the AES key. SHA-256 hashing validates file integrity after decryption.
