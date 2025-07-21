
from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16
KEY = b"this_is_16_bytes"

CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)

# ----------------------------
# Task 1: Understand the padding oracle
# ----------------------------
def padding_oracle(ciphertext: bytes) -> bool:
    if len(ciphertext) % BLOCK_SIZE != 0:
        return False
    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()
        return True
    except (ValueError, TypeError):
        return False

# ----------------------------
# Task 2: Block splitting
# ----------------------------
def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

# ----------------------------
# Task 3: Decrypt single block using padding oracle
# ----------------------------
def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    intermediate = bytearray(BLOCK_SIZE)
    recovered = bytearray(BLOCK_SIZE)
    for byte_index in range(BLOCK_SIZE - 1, -1, -1):
        padding_value = BLOCK_SIZE - byte_index
        for guess in range(256):
            prefix = bytearray(b"\x00" * byte_index)
            guess_block = bytearray(prefix)
            for i in range(BLOCK_SIZE - 1, byte_index, -1):
                guess_block.append(intermediate[i] ^ padding_value)
            guess_block.append(guess ^ padding_value)
            forged_block = bytes(guess_block)
            forged_ciphertext = forged_block + target_block
            if padding_oracle(forged_ciphertext):
                if byte_index == BLOCK_SIZE - 1:
                    altered = bytearray(guess_block)
                    altered[byte_index - 1] ^= 1
                    check_forged = bytes(altered) + target_block
                    if not padding_oracle(check_forged):
                        continue
                intermediate[byte_index] = guess ^ padding_value
                recovered[byte_index] = intermediate[byte_index] ^ prev_block[byte_index]
                break
    return bytes(recovered)

# ----------------------------
# Task 4: Full padding oracle attack
# ----------------------------
def padding_oracle_attack(ciphertext: bytes) -> bytes:
    blocks = split_blocks(ciphertext)
    recovered = bytearray()
    for i in range(1, len(blocks)):
        decrypted_block = decrypt_block(blocks[i - 1], blocks[i])
        recovered.extend(decrypted_block)
    return bytes(recovered)

# ----------------------------
# Task 5: Unpad and decode plaintext
# ----------------------------
def unpad_and_decode(plaintext: bytes) -> str:
    try:
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadded = unpadder.update(plaintext) + unpadder.finalize()
        return unpadded.decode('utf-8')
    except Exception:
        return plaintext.rstrip(bytes(range(1, 17))).decode('utf-8', errors='replace')

if __name__ == "__main__":
    try:
        ciphertext = unhexlify(CIPHERTEXT_HEX)
        print(f"[*] Ciphertext length: {len(ciphertext)} bytes")
        print(f"[*] IV: {ciphertext[:BLOCK_SIZE].hex()}")
        recovered = padding_oracle_attack(ciphertext)
        print("\n[+] Decryption complete!")
        print(f"    Recovered plaintext (raw bytes): {recovered}")
        print(f"    Hex: {recovered.hex()}")
        decoded = unpad_and_decode(recovered)
        print("\n[+] Final plaintext:")
        print(decoded)
    except Exception as e:
        print(f"[!] Error occurred: {e}")
