import os
from generate_keys import generate_rsa_keys
from crypto_utils import encrypt_file, decrypt_file

# Optional imports (if teammates' parts exist)
try:
    from hash_utils import compute_file_hash
except ImportError:
    compute_file_hash = None

try:
    from auth import hash_password, verify_password
except ImportError:
    hash_password = verify_password = None


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def main_menu():
    while True:
        print("\n🔐=== CRYPTOGRAPHY PROJECT MENU ===")
        print("1. Generate RSA Key Pair")
        print("2. Encrypt a File (AES + RSA)")
        print("3. Decrypt a File (AES + RSA)")
        print("4. Compute File Hash (SHA-256)")
        print("5. Exit")
        choice = input("\nEnter your choice (1-5): ")

        if choice == '1':
            generate_rsa_keys()

        elif choice == '2':
            file_path = input("Enter the path of the file to encrypt (e.g., uploads/sample.txt): ").strip()
            if os.path.exists(file_path):
                encrypt_file(file_path)
            else:
                print("⚠️ File not found. Check your path.")

        elif choice == '3':
            enc_file = input("Enter the path of the encrypted file (.enc): ").strip()
            enc_key = input("Enter the path of the encrypted AES key (.key): ").strip()
            if os.path.exists(enc_file) and os.path.exists(enc_key):
                decrypt_file(enc_file, enc_key)
            else:
                print("⚠️ One or both files not found.")

        elif choice == '4':
            if compute_file_hash:
                file_path = input("Enter file path to hash: ").strip()
                if os.path.exists(file_path):
                    hash_val = compute_file_hash(file_path)
                    print(f"SHA-256 Hash:\n{hash_val}")
                else:
                    print("⚠️ File not found.")
            else:
                print("⚠️ hash_utils not yet implemented by Member 2.")

        elif choice == '5':
            print("\nExiting program. Goodbye 👋")
            break

        else:
            print("Invalid choice. Please enter a number between 1 and 5.")


if __name__ == "__main__":
    clear()
    main_menu()

from crypto_utils import encrypt_file, decrypt_file

# Encrypt test file
enc_file, enc_key = encrypt_file("uploads/sample.txt")

# Decrypt it back
decrypt_file(enc_file, enc_key)
