# Advanced Encryption Standard (AES) Implementation
This repository contains the implementation of the **Advanced Encryption Standard (AES)** algorithm for secure data encryption and decryption.

## Overview

This repo demonstrates:
- The process of **encrypting** and **decrypting** data using the **AES symmetric encryption** technique.
- Working with different AES CBC mode.
- Secure handling of plaintext and ciphertext in cryptographic applications.

**AES** is a widely used standard for securing sensitive data and is known for its speed and strong security.

## Features

- Encrypt plaintext using AES encryption.
- Decrypt ciphertext back into the original plaintext.
- Support for key sizes: **128-bit**, **192-bit**, and **256-bit**.

## Technologies Used

- Python 3
- `pycryptodome` library (`Crypto.Cipher.AES`)
- Basic understanding of symmetric key cryptography

## How to Run

1. Install dependencies:
   ```bash
   pip install pycryptodome
   ```

2. Run the AES encryption-decryption script: (give text as input)
   ```bash
   python AES1.py
   ```
3. Run the AES encryption-decryption script: (give text file as input)
   ```bash
   python AES2.py
   ```

4. The script will demonstrate:
   - How plaintext is encrypted to ciphertext
   - How ciphertext is decrypted back to plaintext

## Notes

- AES is the de facto standard for modern data encryption and is used worldwide across industries.
- For maximum security, use **AES-256** with secure key and IV management practices.
- This repo is intended for educational purposes and demonstrates the core principles of AES encryption.
