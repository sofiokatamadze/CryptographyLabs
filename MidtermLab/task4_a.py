from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import hashlib

# Generate common DH parameters
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

# Alice's key pair
alice_private_key = parameters.generate_private_key()
alice_public_key = alice_private_key.public_key()

# Bob's key pair
bob_private_key = parameters.generate_private_key()
bob_public_key = bob_private_key.public_key()

# Exchange and derive shared secret
alice_shared_key = alice_private_key.exchange(bob_public_key)
bob_shared_key = bob_private_key.exchange(alice_public_key)

# Hash the shared secrets
def derive_key(shared_key):
    return hashlib.sha256(shared_key).hexdigest()

alice_final_key = derive_key(alice_shared_key)
bob_final_key = derive_key(bob_shared_key)

# Export keys for documentation
alice_pub_pem = alice_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

bob_pub_pem = bob_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

print("Alice's Public Key:\n", alice_pub_pem)
print("Bob's Public Key:\n", bob_pub_pem)
print("Shared Key (Alice):", alice_final_key)
print("Shared Key (Bob):", bob_final_key)
print("Shared Keys Match:", alice_final_key == bob_final_key)
