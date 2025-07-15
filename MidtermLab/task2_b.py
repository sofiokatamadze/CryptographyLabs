from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

# Step 1: Create message file
with open("ecc.txt", "w") as f:
    f.write("Elliptic Curves are efficient.")

# Read message
with open("ecc.txt", "rb") as f:
    message = f.read()

# Step 2: Load private key
with open("ecc_private_key.pem", "rb") as f:
    private_key = load_pem_private_key(f.read(), password=None)

# Sign message
signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

with open("ecc_signature.bin", "wb") as f:
    f.write(signature)

print("Message signed and saved as ecc_signature.bin")

# Step 3: Load public key and verify
with open("ecc_public_key.pem", "rb") as f:
    public_key = load_pem_public_key(f.read())

try:
    public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    print("Signature successfully verified!")
except Exception as e:
    print("Signature verification failed:", e)
