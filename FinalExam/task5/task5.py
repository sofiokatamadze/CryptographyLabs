import hashlib
import json

def compute_hashes(file_path):
    """Compute SHA-256, SHA-1, and MD5 hashes for a file."""
    hashes = {
        "SHA256": "",
        "SHA1": "",
        "MD5": ""
    }
    with open(file_path, "rb") as f:
        data = f.read()
        hashes["SHA256"] = hashlib.sha256(data).hexdigest()
        hashes["SHA1"] = hashlib.sha1(data).hexdigest()
        hashes["MD5"] = hashlib.md5(data).hexdigest()
    return hashes

def save_hashes(file_path, hashes):
    """Save hashes to a JSON file."""
    with open(file_path, "w") as f:
        json.dump(hashes, f, indent=4)

def load_hashes(file_path):
    """Load hashes from a JSON file."""
    with open(file_path, "r") as f:
        return json.load(f)

def main():
    # Step 1: Hash original.txt and store
    orig_hashes = compute_hashes("original.txt")
    save_hashes("hashes.json", orig_hashes)
    print("Original file hashes saved to hashes.json")

    # Step 2: Hash tampered.txt and compare
    tampered_hashes = compute_hashes("tampered.txt")
    reference_hashes = load_hashes("hashes.json")
    print("Hashes for tampered.txt computed:")

    # Step 3: Detect tampering
    match = tampered_hashes == reference_hashes
    print("Integrity check result: " + ("PASS" if match else "FAIL"))
    if not match:
        print("Warning: File has been modified (tampering detected)!")
    else:
        print("No modification detected.")

if __name__ == "__main__":
    main()
