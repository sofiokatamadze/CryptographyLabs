# Task 1: Encrypted Messaging App Prototype

## Overview
This task demonstrates a hybrid encryption system using RSA and AES. It simulates secure message transfer from User B to User A.

## Encryption Flow

### Step 1: Key Generation
- User A generates an RSA key pair (private and public keys).
- The public key is shared with User B.

### Step 2: Message Encryption (by User B)
- User B creates a plaintext message (`message.txt`).
- An AES-256 symmetric key is generated randomly.
- The message is encrypted using AES-256 in CBC mode and saved as `encrypted_message.bin`.
- The AES key is then encrypted with User A’s RSA public key and stored in `aes_key_encrypted.bin`.

### Step 3: Message Decryption (by User A)
- User A decrypts the AES key using their RSA private key.
- Then decrypts the AES-encrypted message using the decrypted AES key.
- The result is written to `decrypted_message.txt`.

## Files
- `message.txt` - Original plaintext message from User B.
- `encrypted_message.bin` - AES-encrypted message.
- `aes_key_encrypted.bin` - AES key encrypted with RSA.
- `decrypted_message.txt` - Final decrypted message.
- `task1_messaging_app.py` - Complete encryption/decryption Python code.

## Security Summary
- RSA ensures secure key exchange.
- AES provides efficient encryption for the actual message.
- This hybrid model is widely used in real-world secure communication.