# 🔐 CryptoShield

### A Secure Data Storage and Transmission System

CryptoShield is a Python-based security application that protects data during **storage and transmission** using modern cryptographic techniques.

## ✨ Features

* 🔒 Password-based encryption (PBKDF2-HMAC-SHA256 + HKDF -> ChaCha20-Poly1305)
* 🛡️ Data integrity verification (SHA-256)
* 🔑 Authentication (HMAC-SHA256)
* 🚨 Tamper detection and demo ("Test Tamper")
* 👤 User registration, login and logout (hashed passwords, Flask sessions)
* 📁 Per-user encrypted storage - users cannot see each other's data
* 📝 Audit log with usernames (never passwords or keys)
* 🙈 Cryptographic keys are never shown in the UI

## 🛠️ Technologies

* Python
* Flask
* Cryptography Library
* SQLite (built into Python)
* HTML, CSS, JavaScript

## ⚙️ Run the Project

```bash
git clone https://github.com/dhanashree340-cmyk/cryptoshield.git
cd cryptoshield
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`, click **Create an account**, register, log in, then encrypt and decrypt.

The old `master.key` file is no longer used - delete it.

**Dhanashree Naik**
