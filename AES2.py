#Take file as input
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
key = b"#@TOPSECRETKEY!!"

def encrypt_file(input_file, output_file, key):
    with open(input_file, 'r', encoding='utf-8') as f:
        plaintext = f.read()
    
    cipher = AES.new(key, AES.MODE_CBC)  # Random IV
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(base64.b64encode(cipher.iv + ciphertext).decode())
    print(f"Encrypted content saved to {output_file}")

def decrypt_file(input_file, output_file, key):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            ciphertext_b64 = f.read()
        
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = ciphertext[:AES.block_size]  # Get IV
        encrypted_message = ciphertext[AES.block_size:]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(encrypted_message), AES.block_size)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(plaintext.decode())
        print(f"Decrypted content saved to {output_file}")
    except ValueError:
        print("Decryption error!")

def main():
        input_file = input("Enter plaintext file path: ").strip()
        output_file = input("Enter output encrypted file path: ").strip()
        encrypt_file(input_file, output_file, key)

        input_file = input("Enter encrypted file path: ").strip()
        output_file = input("Enter output decrypted file path: ").strip()
        decrypt_file(input_file, output_file, key)

if __name__ == "__main__":
    main()
