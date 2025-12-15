# Cryptographic Security Framework

Python-based cryptographic framework to encrypt files and detect unauthorized file tampering using AES encryption and SHA-256 integrity checks.

---

## 📌 Overview

The Cryptographic Security Framework is a lightweight security tool designed to protect files and detect unauthorized modifications. It combines encryption and cryptographic hashing to ensure both confidentiality and integrity of data. This project simulates real-world SOC and incident response scenarios where file tampering is a common malware technique.

---

## ✨ Features

- AES-based file encryption and decryption
- Secure encryption key generation
- SHA-256 hash generation for file integrity
- File integrity verification
- Tamper detection alerts
- Security event logging

---

## 🛠️ Technologies Used

- Python 3
- Cryptography Library
- AES (Advanced Encryption Standard)
- SHA-256 Hash Algorithm
- Visual Studio Code
- Windows PowerShell

---

## 📂 Project Structure

cryptographic-security-framework/
│
├── crypto_framework.py
├── README.md
├── LICENSE
└── .gitignore

---

## ⚙️ Requirements

- Python 3.x
- cryptography library

Install dependency using:
pip install cryptography

---

## 🚀 Usage

Generate encryption key:
python crypto_framework.py --genkey

Encrypt a file:
python crypto_framework.py --encrypt test.txt

Decrypt a file:
python crypto_framework.py --decrypt test.txt.enc

Generate SHA-256 hash:
python crypto_framework.py --hash test.txt

Verify file integrity:
python crypto_framework.py --verify test.txt

---

## 🔐 Security Use Case

This framework can be used to:
- Detect malware-driven file tampering
- Validate file integrity during incident response
- Protect sensitive files from unauthorized access
- Simulate SOC-style file integrity monitoring

---

## ⚠️ Important Notes

Do NOT upload encryption keys or log files to public repositories.

Add the following to .gitignore:
secret.key
*.log

---

## 📈 Future Enhancements

- Real-time file integrity monitoring
- Integration with SIEM tools (Splunk / Wazuh)
- Ransomware behavior detection
- Graphical User Interface (GUI)

---

## 📄 License

This project is licensed under the MIT License.

---

## 👤 Author

Harnil Modi  
Cybersecurity Enthusiast | SOC Analyst Intern Aspirant
