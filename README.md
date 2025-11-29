**SecureEncryptionSystem**

**Project:**: A small Flask-based web application for encrypting and decrypting files using AES-256-CBC with PBKDF2-derived keys.

**Overview:**: This project provides a minimal web UI to upload a file and either encrypt or decrypt it using a password. The cryptographic primitives live in `crypto_engine.py` and the Flask web interface is in `app.py`.

**Key Features:**

- **Encryption:**: AES-256-CBC with PKCS#7 padding (via PyCryptodome).
- **Key Derivation:**: PBKDF2 with a 16-byte salt and 200,000 iterations to derive a 256-bit key from the user password.
- **Integrity:**: SHA-256 hashing for optional integrity verification (stored in session during encrypt → decrypt flow).
- **Simple Web UI:**: A single-page form implemented in `templates/index.html` served by `app.py`.

**Repository Files:**

- `app.py`: Flask application, routes for `/` and `/process`, and helper functions `handle_encryption` and `handle_decryption`.
- `crypto_engine.py`: Crypto primitives: `derive_key`, `encrypt_data`, `decrypt_data`, `compute_hash`, `verify_integrity`, etc.
- `templates/index.html`: Minimal HTML form for uploading files and choosing encrypt/decrypt.

**Encrypted File Format:**

- Output bytes layout: `salt (16 bytes) || iv (16 bytes) || ciphertext`.
- During encryption the app writes this combined blob to a file named `encrypted_<original_filename>.enc`.

**Security Notes (important):**

- The app uses PBKDF2 with `200000` iterations and a 16-byte salt by default.
- The Flask `secret_key` in `app.py` is generated using `secrets.token_hex(32)`; for production, provide a stable, secure key via environment variable.
- Session-based integrity verification is convenient for demo flows but not appropriate for cross-client verification. Use authenticated metadata or detached signatures for robust integrity checks in production.
- This project is a learning/demo implementation. Do not use it as-is for protecting high-value secrets without a security review.

**Requirements:**

- Python 3.8+ (3.9+ recommended)
- `pip` and a virtual environment
- Python packages: `Flask`, `pycryptodome`

**Quick Setup (macOS / zsh)**
Install into a virtual environment and run:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install Flask pycryptodome
```

**Run the app (development):**

```bash
# from project root
export FLASK_APP=app.py
# optionally keep debugging off or on depending on needs
python app.py
# then open http://127.0.0.1:5000 in your browser
```

**Usage:**

- Open the web UI at `http://127.0.0.1:5000`.
- Choose a file, enter a password, pick `Encrypt` or `Decrypt`, and submit.
- Encrypted files are created as `encrypted_<original_filename>.enc` and served for download; decrypted files are named `decrypted_<original_filename>`.

**Developer Notes:**

- The `crypto_engine.py` functions are small and focused — unit tests can be added to verify behavior of `derive_key`, `encrypt_data`, `decrypt_data`, and `verify_integrity`.
- The encryption parameters (`PBKDF2_ITERATIONS`, `SALT_SIZE`, `IV_SIZE`, `KEY_SIZE`) are defined at top of `crypto_engine.py` for easy tuning.

**Next steps / Suggestions:**

- Add tests and CI to verify crypto correctness and edge cases.
- Add environment-based configuration for secrets and production settings.
- Replace session-based integrity verification with authenticated metadata (e.g., HMAC or digital signatures) saved alongside the encrypted blob.

**License & Contact:**

- This repository does not include a license file. Add one if you intend to publish.
- For questions or follow-ups, edit this README or open an issue in the repo.
