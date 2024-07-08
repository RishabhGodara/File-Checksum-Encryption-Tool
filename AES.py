from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from hashlib import sha256

class AEScipher:
    def __init__(self, key):
        self.key = sha256(key.encode("utf-8")).digest()

    def encryption(self, file_path):
        iv = get_random_bytes(16)
        with open(file_path, "rb") as file:
            file_data = file.read()
        
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
        
        with open(file_path + ".enc", "wb") as file:
            file.write(iv + encrypted_data)

    def decryption(self, encrypted_file_path):
        with open(encrypted_file_path, "rb") as file:
            encrypted_data = file.read()
        
        iv = encrypted_data[:16]
        encrypted_data = encrypted_data[16:]
        
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        
        plain_file_path = encrypted_file_path.replace(".enc", "")
        with open(plain_file_path + "Decrypted", "wb") as file:
            file.write(decrypted_data)

if __name__ == "__main__":
    """
    key = "your_key"  # Provide key
    aes = AEScipher(key)
    
    plain_file_path = "your_plain_file_path"
    aes.encryption(plain_file_path)
    
    encrypted_file_path = "your_encrypted_file_path"
    decrypted_text = aes.decryption(encrypted_file_path)
    """
