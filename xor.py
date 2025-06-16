import base64

def xor_decrypt_base64(cipher_b64, key):
    cipher_bytes = base64.b64decode(cipher_b64)
    key_bytes = key.encode()
    decrypted = bytearray()

    for i in range(len(cipher_bytes)):
        decrypted.append(cipher_bytes[i] ^ key_bytes[i % len(key_bytes)])

    return decrypted.decode(errors='ignore')

cipher_b64 = "Jw0KBlIMAEUXHRdFKyoxVRENEgkPEBwCFkQ="
key = "secure"

# Task3
print(xor_decrypt_base64(cipher_b64, key))
