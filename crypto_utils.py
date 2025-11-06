from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os

# AES + RSA Encryption System
def encrypt_file(file_path, public_key_path="keys/rsa_public.pem"):
    # Load RSA public key
    with open(public_key_path, "rb") as key_file:
        public_key = RSA.import_key(key_file.read())

    # Generate AES key and IV
    aes_key = get_random_bytes(32)  # 256-bit key
    iv = get_random_bytes(16)

    # Encrypt the AES key using RSA
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    # Encrypt file data with AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    with open(file_path, "rb") as f:
        plaintext = f.read()

    # Padding for AES block size (16 bytes)
    pad_len = 16 - len(plaintext) % 16
    plaintext += bytes([pad_len]) * pad_len
    ciphertext = cipher_aes.encrypt(plaintext)

    # Save encrypted file with IV prepended
    filename = os.path.basename(file_path)
    enc_file_path = f"uploads/encrypted_files/{filename}.enc"
    with open(enc_file_path, "wb") as f:
        f.write(iv + ciphertext)

    # Save encrypted AES key
    with open(f"uploads/encrypted_files/{filename}.key", "wb") as f:
        f.write(enc_aes_key)

    print(f"File '{filename}' encrypted successfully.")
    print(f"→ Encrypted file: {enc_file_path}")
    print(f"→ Encrypted AES key saved.")

    return enc_file_path, f"uploads/encrypted_files/{filename}.key"

def decrypt_file(enc_file_path, enc_key_path, private_key_path="keys/rsa_private.pem"):
    # Load RSA private key
    with open(private_key_path, "rb") as key_file:
        private_key = RSA.import_key(key_file.read())

    # Decrypt AES key
    with open(enc_key_path, "rb") as f:
        enc_aes_key = f.read()
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)

    # Read encrypted file and extract IV
    with open(enc_file_path, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()

    # AES decryption
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext_padded = cipher_aes.decrypt(ciphertext)

    # Remove padding
    pad_len = plaintext_padded[-1]
    plaintext = plaintext_padded[:-pad_len]

    # Save decrypted file
    filename = os.path.basename(enc_file_path).replace(".enc", "")
    dec_file_path = f"uploads/decrypted_files/{filename}"
    with open(dec_file_path, "wb") as f:
        f.write(plaintext)

    print(f"File '{filename}' decrypted successfully.")
    print(f"→ Decrypted file: {dec_file_path}")

    return dec_file_path

from tqdm import tqdm
for i in tqdm(range(100), desc="Encrypting..."):
    pass
