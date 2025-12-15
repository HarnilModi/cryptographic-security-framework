import os
import hashlib
import logging
from cryptography.fernet import Fernet
import argparse

# ---------------- LOGGING SETUP ----------------
logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ---------------- KEY GENERATION ----------------
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    logging.info("Encryption key generated")
    print("[+] Key generated and saved as secret.key")

def load_key():
    return open("secret.key", "rb").read()

# ---------------- FILE ENCRYPTION ----------------
def encrypt_file(filename):
    key = load_key()
    fernet = Fernet(key)

    with open(filename, "rb") as file:
        original_data = file.read()

    encrypted_data = fernet.encrypt(original_data)

    with open(filename + ".enc", "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    logging.info(f"File encrypted: {filename}")
    print("[+] File encrypted successfully")

# ---------------- FILE DECRYPTION ----------------
def decrypt_file(filename):
    key = load_key()
    fernet = Fernet(key)

    with open(filename, "rb") as enc_file:
        encrypted_data = enc_file.read()

    decrypted_data = fernet.decrypt(encrypted_data)

    output_file = filename.replace(".enc", "")

    with open(output_file, "wb") as dec_file:
        dec_file.write(decrypted_data)

    logging.info(f"File decrypted: {filename}")
    print("[+] File decrypted successfully")

# ---------------- HASH GENERATION ----------------
def generate_hash(filename):
    sha256 = hashlib.sha256()

    with open(filename, "rb") as file:
        for block in iter(lambda: file.read(4096), b""):
            sha256.update(block)

    file_hash = sha256.hexdigest()

    with open(filename + ".hash", "w") as hash_file:
        hash_file.write(file_hash)

    logging.info(f"Hash generated for: {filename}")
    print("[+] SHA-256 Hash generated")

# ---------------- TAMPER DETECTION ----------------
def verify_hash(filename):
    sha256 = hashlib.sha256()

    with open(filename, "rb") as file:
        for block in iter(lambda: file.read(4096), b""):
            sha256.update(block)

    current_hash = sha256.hexdigest()

    with open(filename + ".hash", "r") as hash_file:
        original_hash = hash_file.read()

    if current_hash == original_hash:
        logging.info(f"Integrity verified: {filename}")
        print("[+] File integrity verified (No tampering)")
    else:
        logging.warning(f"Tampering detected: {filename}")
        print("[!] ALERT: File tampering detected!")

# ---------------- COMMAND LINE ----------------
def main():
    parser = argparse.ArgumentParser(description="Cryptographic Security Framework")
    parser.add_argument("--genkey", action="store_true", help="Generate encryption key")
    parser.add_argument("--encrypt", help="Encrypt a file")
    parser.add_argument("--decrypt", help="Decrypt a file")
    parser.add_argument("--hash", help="Generate SHA-256 hash of file")
    parser.add_argument("--verify", help="Verify file integrity")

    args = parser.parse_args()

    if args.genkey:
        generate_key()
    elif args.encrypt:
        encrypt_file(args.encrypt)
    elif args.decrypt:
        decrypt_file(args.decrypt)
    elif args.hash:
        generate_hash(args.hash)
    elif args.verify:
        verify_hash(args.verify)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
