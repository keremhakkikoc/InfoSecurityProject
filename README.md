# Secure Zero-Trust File Drop System

This project is an implementation of a secure file drop system using a zero-trust storage assumption, fulfilling the requirements for the **CSE 4057 Programming Assignment**.

## Project Details
- **Assignment**: CSE 4057, Spring 2026
- **Due Date**: 24.05.2026

## Team Members
- [Your Name] - Team Leader
- [Member 2 Name] 
- [Member 3 Name]

## Architecture & Implementation Overview

### 1) Public Key Infrastructure and Certificate Handling
We created a minimal Certificate Authority (`ca.py`) using the `cryptography` library. 
The CA generates its own self-signed RSA-2048 certificate. Both the server and the clients generate their RSA-2048 keypairs and have their public keys signed by this CA, producing standards-compliant X.509 certificates.

### 2) Secure Handshake and Session Key Establishment
We designed a custom application-layer handshake protocol to perform mutual authentication over a raw TCP socket, strictly without using SSL/TLS libraries.
- **ClientHello**: Client sends its CA-signed Certificate and a 16-byte random `Nonce_C`.
- **ServerHello**: Server verifies the client's certificate. Sends its Certificate, a random `Nonce_S`, and a digital signature of `(Nonce_C + Nonce_S)` to prove possession of the private key.
- **ClientKeyExchange**: Client verifies the Server's certificate and signature. Client generates a 32-byte `PreMasterSecret`, encrypts it with the Server's Public RSA Key, and generates a digital signature of `(Nonce_C + Nonce_S + PreMasterSecret)`.
- **Key Derivation (HKDF)**: Both parties apply HMAC-based Key Derivation Function (HKDF-SHA256) over the `PreMasterSecret` using the nonces as a salt. This yields symmetric AES keys (`ClientToServerKey`, `ServerToClientKey`).

### 3) Secure File Encryption and Upload (TODO)
*(This section will be detailed when implemented)*

### 4) Digital Signature and Integrity Verification (TODO)
*(This section will be detailed when implemented)*

### 5) Secure Retrieval and Access Control (TODO)
*(This section will be detailed when implemented)*

### 6) File Expiration (TODO)
*(This section will be detailed when implemented)*

### 7) Replay Protection and Freshness
Replay attacks are mitigated during the handshake by using randomly generated 16-byte nonces from both sides (`Nonce_C` and `Nonce_S`). Since every session uses fresh nonces, any recorded handshake cannot be replayed successfully because the signatures will not match the new nonces.

### Security Analysis
*(To be written)*

## How to Run

**1. Setup & Install Dependencies**
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**2. Generate Certificates**
Run the CA script to generate the Root CA and necessary entity keys in the `certs/` directory:
```bash
python ca.py
```

**3. Run the Server**
```bash
python server.py
```

**4. Run a Client**
```bash
python client.py
```
