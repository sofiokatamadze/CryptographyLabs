from hashlib import sha256
import hmac

# === Task 3A: SHA-256 Hash ===
original_message = "Never trust, always verify."
with open("data.txt", "w") as f:
    f.write(original_message)

with open("data.txt", "rb") as f:
    original_bytes = f.read()

sha256_hash = sha256(original_bytes).hexdigest()
print("[Task 3A] SHA-256 Hash of original message:")
print(sha256_hash)

# === Task 3B: HMAC using SHA-256 ===
key = b"secretkey123"
hmac_original = hmac.new(key, original_bytes, sha256).hexdigest()
print("\n[Task 3B] HMAC-SHA256 of original message:")
print(hmac_original)

# === Task 3C: Integrity Check ===
# Change one letter
tampered_message = "Never trust, always verifx."
with open("data.txt", "w") as f:
    f.write(tampered_message)

with open("data.txt", "rb") as f:
    tampered_bytes = f.read()

hmac_tampered = hmac.new(key, tampered_bytes, sha256).hexdigest()
print("\n[Task 3C] HMAC-SHA256 of tampered message:")
print(hmac_tampered)

# Compare HMACs
if hmac_original != hmac_tampered:
    print("\n Integrity check: HMAC mismatch detected. File was modified.")
    print("Explanation: HMAC provides message authentication and integrity verification. "
          "Any change in the content results in a different HMAC.")
else:
    print("\n Integrity check: HMACs match (unexpected).")
