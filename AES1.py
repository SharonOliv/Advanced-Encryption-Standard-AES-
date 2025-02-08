#Take text as input
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

key = b"#@TOPSECRETKEY!!"
def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)  #Random iv
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode() 

def decrypt(ciphertext_b64, key):
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = ciphertext[:AES.block_size]  #get iv 
        encrypted_message = ciphertext[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(encrypted_message), AES.block_size)
        return plaintext.decode()
    except ValueError:
        return "Decryption error!"

def main():
    plaintext = input("Enter text to encrypt: ")
    encrypted_message = encrypt(plaintext, key)
    print(f"Encrypted (Base64): {encrypted_message}")

    ciphertext = input("Enter text to decrypt: ")
    decrypted_message = decrypt(ciphertext, key)
    print(f"Decrypted: {decrypted_message}")

if __name__ == "__main__":
    main()
