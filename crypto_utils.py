# crypto_utils.py
import os
from typing import Tuple
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

# Directories (adjust if needed)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
KEYS_DIR = os.path.join(BASE_DIR, "keys")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
ENCRYPTED_DIR = os.path.join(BASE_DIR, 'uploads', "encrypted")
DECRYPTED_DIR = os.path.join(UPLOADS_DIR, "decrypted")
ORIGINAL_DIR = os.path.join(UPLOADS_DIR, "original")
AESKEYS_DIR = os.path.join(UPLOADS_DIR, "aes_keys")  # stores encrypted AES keys

# Ensure directories exist
for d in (KEYS_DIR, UPLOADS_DIR, ENCRYPTED_DIR, DECRYPTED_DIR, ORIGINAL_DIR, AESKEYS_DIR):
    os.makedirs(d, exist_ok=True)


# -----------------------------
# RSA Key generation / loading
# -----------------------------
def generate_rsa_keypair(bits: int = 2048, pub_name: str = "rsa_public.pem", priv_name: str = "rsa_private.pem") -> Tuple[str, str]:
    """
    Generate RSA keypair and save to keys/ directory.
    Returns (pub_path, priv_path).
    """
    key = RSA.generate(bits)
    private_key = key.export_key(pkcs=8)  # PKCS#8 format
    public_key = key.publickey().export_key()

    priv_path = os.path.join(KEYS_DIR, priv_name)
    pub_path = os.path.join(KEYS_DIR, pub_name)

    with open(priv_path, "wb") as f:
        f.write(private_key)
    with open(pub_path, "wb") as f:
        f.write(public_key)

    return pub_path, priv_path


def load_rsa_public_key(pub_path: str = None) -> RSA.RsaKey:
    p = pub_path or os.path.join(KEYS_DIR, "rsa_public.pem")
    with open(p, "rb") as f:
        return RSA.import_key(f.read())


def load_rsa_private_key(priv_path: str = None) -> RSA.RsaKey:
    p = priv_path or os.path.join(KEYS_DIR, "rsa_private.pem")
    with open(p, "rb") as f:
        return RSA.import_key(f.read())


# -------------------------------------
# AES key / IV generation (AES-256 GCM)
# -------------------------------------
def generate_aes_key() -> bytes:
    """Return a 32-byte AES-256 key."""
    return get_random_bytes(32)


def generate_aes_nonce() -> bytes:
    """Return a recommended 12-byte nonce for GCM."""
    return get_random_bytes(12)


# -----------------------
# SHA-256 file fingerprint
# -----------------------
def sha256_file(path: str) -> str:
    """
    Compute SHA-256 hex digest of file at path.
    Returns hex string.
    """
    h = SHA256.new()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ----------------------------
# Encrypt AES key with RSA OAEP
# ----------------------------
def encrypt_aes_key_with_rsa(aes_key: bytes, pub_path: str = None) -> bytes:
    pub = load_rsa_public_key(pub_path)
    cipher_rsa = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    enc_key = cipher_rsa.encrypt(aes_key)
    return enc_key


def decrypt_aes_key_with_rsa(enc_key: bytes, priv_path: str = None) -> bytes:
    priv = load_rsa_private_key(priv_path)
    cipher_rsa = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    aes_key = cipher_rsa.decrypt(enc_key)
    return aes_key


# ---------------------------------
# Encrypt / decrypt files with AES
# Using AES-GCM: stored format -> nonce||tag||ciphertext
# ---------------------------------
def encrypt_file_aes_gcm(input_path: str, output_path: str, aes_key: bytes) -> Tuple[bytes, int]:
    """
    Encrypt input_path -> output_path using AES-GCM.
    Returns (nonce, total_bytes_written).
    Stored layout in output file: 12-byte nonce | 16-byte tag | ciphertext
    """
    nonce = generate_aes_nonce()
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    total_written = 0
    with open(input_path, "rb") as f_in:
        plaintext = f_in.read()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    with open(output_path, "wb") as f_out:
        f_out.write(nonce)
        f_out.write(tag)
        f_out.write(ciphertext)
        total_written = len(nonce) + len(tag) + len(ciphertext)

    return nonce, total_written


def decrypt_file_aes_gcm(encrypted_path: str, output_path: str, aes_key: bytes) -> None:
    """
    Decrypt file written as nonce|tag|ciphertext and write plaintext to output_path.
    Raises ValueError if tag check fails.
    """
    with open(encrypted_path, "rb") as f:
        nonce = f.read(12)
        tag = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    with open(output_path, "wb") as f_out:
        f_out.write(plaintext)


# ----------------------------
# High-level helpers for Flask
# ----------------------------
def handle_upload_and_encrypt(file_storage, filename: str = None) -> dict:
    """
    Given a Werkzeug FileStorage (from Flask request.files['file']),
    saves original file, computes SHA-256, encrypts file with AES-256-GCM,
    encrypts AES key with RSA public key, and writes artifacts to uploads/.
    Returns metadata dict with paths and hash.
    """
    if filename is None:
        filename = file_storage.filename

    # Save original
    original_path = os.path.join(ORIGINAL_DIR, filename)
    file_storage.save(original_path)

    # Compute SHA-256 of original
    fingerprint = sha256_file(original_path)

    # Generate AES key and encrypt file
    aes_key = generate_aes_key()
    encrypted_filename = filename + ".enc"
    encrypted_path = os.path.join(ENCRYPTED_DIR, encrypted_filename)
    nonce, size = encrypt_file_aes_gcm(original_path, encrypted_path, aes_key)

    # Encrypt AES key with RSA public key
    enc_aes_key = encrypt_aes_key_with_rsa(aes_key)
    aes_key_file = os.path.join(AESKEYS_DIR, filename + ".key.enc")
    with open(aes_key_file, "wb") as kf:
        kf.write(enc_aes_key)

    # Metadata to store (e.g., DB row or JSON)
    meta = {
        "original_path": original_path,
        "fingerprint_sha256": fingerprint,
        "encrypted_path": encrypted_path,
        "aes_key_encrypted_path": aes_key_file,
        "nonce_bytes": len(nonce),
        "encrypted_size": size,
        "filename": filename,
        "encrypted_filename": encrypted_filename,
    }
    return meta


def handle_decrypt_and_verify(filename: str, priv_path: str = None) -> dict:
    """
    Given original filename (as uploaded), find encrypted file and AES key,
    decrypt AES key with RSA private key, decrypt file, compute hash and compare.
    Returns metadata including verification result and path to decrypted file.
    """
    encrypted_path = os.path.join(ENCRYPTED_DIR, filename + ".enc")
    aes_key_file = os.path.join(AESKEYS_DIR, filename + ".key.enc")
    if not os.path.exists(encrypted_path) or not os.path.exists(aes_key_file):
        raise FileNotFoundError("Encrypted file or encrypted AES key not found.")

    # Read encrypted AES key and decrypt with RSA private key
    with open(aes_key_file, "rb") as f:
        enc_aes_key = f.read()

    aes_key = decrypt_aes_key_with_rsa(enc_aes_key, priv_path)

    # Decrypt file to decrypted_files/<filename>
    decrypted_path = os.path.join(DECRYPTED_DIR, filename + ".dec")
    decrypt_file_aes_gcm(encrypted_path, decrypted_path, aes_key)

    # Compute SHA-256 of decrypted and of original (if original exists)
    decrypted_hash = sha256_file(decrypted_path)
    original_path = os.path.join(ORIGINAL_DIR, filename)
    original_hash = sha256_file(original_path) if os.path.exists(original_path) else None

    verified = (original_hash is not None and original_hash == decrypted_hash)

    return {
        "decrypted_path": decrypted_path,
        "original_hash": original_hash,
        "decrypted_hash": decrypted_hash,
        "verified": verified,
    }


# Utility: list encrypted files (simple)
def list_encrypted_files():
    out = []
    for fname in os.listdir(ENCRYPTED_DIR):
        if fname.endswith(".enc"):
            # filename without .enc
            out.append(fname[:-4])
    return out

def list_encrypted_files():
    out = []
    for fname in os.listdir(ENCRYPTED_DIR):
        if fname.endswith(".enc"):
            out.append({
                "name": fname[:-4],  # without .enc
                "method": "AES",     # since only AES is implemented
            })
    return out

def list_encrypted_files():
    files = [f[:-4] for f in os.listdir(ENCRYPTED_DIR) if f.endswith(".enc")]
    files.sort(key=lambda f: os.path.getmtime(os.path.join(ENCRYPTED_DIR, f + ".enc")), reverse=True)  # newest first
    return files
