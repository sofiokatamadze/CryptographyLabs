def caesar_decrypt(cipher_text, shift):
    decrypted_text = ""
    for char in cipher_text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            decrypted_text += chr((ord(char) - offset - shift) % 26 + offset)
        else:
            decrypted_text += char
    return decrypted_text

cipher_text = "Hvs Eiwqy Pfckb Tcl Xiadg Cjsf Hvs Zonm Rcu."

# Task1
for shift in range(1, 26):
    decrypted = caesar_decrypt(cipher_text, shift)
    print(f"Task1 - Shift {shift}: {decrypted}")

# Task2
cipher_text = "mznxpz"
for shift in range(1, 26):
    decrypted = caesar_decrypt(cipher_text, shift)
    print(f"Task2 - Shift {shift}: {decrypted}")