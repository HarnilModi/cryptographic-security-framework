# Cryptographic Security Framework

Python-based cryptographic framework to encrypt files and detect unauthorized file tampering using AES encryption and SHA-256 integrity checks.

## Features
- AES file encryption and decryption
- SHA-256 hash generation
- File integrity verification
- Tamper detection alerts
- Security event logging

## Requirements
- Python 3.x
- cryptography library

## Usage
```bash
python crypto_framework.py --genkey
python crypto_framework.py --encrypt test.txt
python crypto_framework.py --hash test.txt
python crypto_framework.py --verify test.txt
