# Encrypted File Transfer & Secure File Storage

This repository implements encrypted upload/download of files between a client and server using AES and HMAC, with chunking, resume support, and a secure channel.

## Files
- `server.py` – Flask server handling storage and retrieval
- `client.py` – command‑line tool for uploading/downloading
- `crypto_utils.py` – AES‑CBC & HMAC helpers
- `storage/` – server-side encrypted storage directory
- `requirements.txt` – Python dependencies

## Setup & Run
1. Install requirements:
   ```powershell
   pip install -r requirements.txt
   ```
2. (Optional) generate TLS cert:
   ```powershell
   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
   ```
3. Run server:
   ```powershell
   python server.py
   ```
4. Use client:
   ```powershell
   python client.py upload path\to\file
   python client.py download filename dest\path
   ```

## Threat Model & Mitigations
(see earlier discussion section from previous notes)
