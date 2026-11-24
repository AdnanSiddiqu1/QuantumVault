# QuantumVault - Post-Quantum Cryptography Engine

## 1. Overview

The QuantumVault PQC Engine is a C-based cryptographic component
that demonstrates post-quantum key establishment and secure data
encryption.

It uses liboqs for post-quantum cryptography and OpenSSL for
symmetric encryption.

The engine is designed to explore protection against Harvest Now,
Decrypt Later (HNDL) attacks.

## 2. Technologies Used

- C Programming Language
- liboqs 0.16.0
- ML-KEM-768
- OpenSSL 3.x
- AES-256-GCM
- GCC

## 3. Implemented Features

### ML-KEM-768 Key Establishment

- Generates public and secret key pairs.
- Performs key encapsulation.
- Performs key decapsulation.
- Verifies that sender and receiver obtain matching shared secrets.

### AES-256-GCM Encryption

- Generates a random 12-byte nonce.
- Encrypts plaintext using AES-256-GCM.
- Generates a 16-byte authentication tag.
- Decrypts ciphertext using the recovered shared secret.
- Verifies the authentication tag during decryption.

### Secure Memory Management

- Uses centralized cleanup paths.
- Handles memory allocation and cryptographic operation failures.
- Securely frees secret keys and shared-secret buffers.
- Cleanses temporary encryption and decryption buffers.

## 4. Project Files

| File | Description |
|---|---|
| kem_demo.c | ML-KEM-768 key generation and shared-secret verification |
| pqc_encrypt_demo.c | ML-KEM-768 and AES-256-GCM encryption/decryption |
| ../tests/test_gcm_tampering.c | Tests ciphertext tampering detection |
| ../tests/test_gcm_tag_tampering.c | Tests authentication-tag tampering detection |

## 5. Compilation

### Compile the KEM Demo

```bash
gcc -Wall -Wextra -Wpedantic pqc-engine/kem_demo.c \
-o pqc-engine/kem_demo $(pkg-config --cflags --libs liboqs)
