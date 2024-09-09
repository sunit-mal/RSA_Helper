import base64
import os
import re
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES

PASSWORD = "Demo@123"
ALGORITHM = "RSA"
AES_ALGORITHM = "AES"
TRANSFORMATION = "AES/CFB/NoPadding"
PADDING_STYLE = padding.PKCS1v15()

def encrypt_data(data):
    public_key = load_public_key()
    cipher_text = public_key.encrypt(
        data.encode('utf-8'),
        PADDING_STYLE
    )
    return base64.b64encode(cipher_text).decode('utf-8')

def load_public_key():
    with open("public.key.enc", "rb") as f:
        encrypted_key_bytes = f.read()
    key_bytes = decrypt_file(encrypted_key_bytes, PASSWORD)
    key_string = key_bytes.decode('utf-8')
    
    key_string = re.sub(r"-----BEGIN PUBLIC KEY-----", "", key_string)
    key_string = re.sub(r"-----END PUBLIC KEY-----", "", key_string)
    key_string = re.sub(r"\s", "", key_string)
    
    decoded_key = base64.b64decode(key_string)
    public_key = serialization.load_der_public_key(decoded_key, backend=default_backend())
    return public_key

def load_private_key():
    with open("private.key.enc", "rb") as f:
        encrypted_key_bytes = f.read()
    key_bytes = decrypt_file(encrypted_key_bytes, PASSWORD)
    key_string = key_bytes.decode('utf-8')

    key_string = re.sub(r"-----BEGIN PRIVATE KEY-----", "", key_string)
    key_string = re.sub(r"-----END PRIVATE KEY-----", "", key_string)
    key_string = re.sub(r"\s", "", key_string)

    decoded_key = base64.b64decode(key_string)
    private_key = serialization.load_der_private_key(decoded_key, password=None, backend=default_backend())
    return private_key

def decrypt_file(encrypted_file_path, password):
    file_bytes = encrypted_file_path
    salt = file_bytes[:16]
    iv = file_bytes[16:32]
    encrypted_data = file_bytes[32:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    return remove_padding(decrypted_data)

def remove_padding(data):
    padding_length = data[-1]
    if padding_length < 1 or padding_length > 16:
        raise ValueError("Invalid padding length")
    
    for i in range(len(data) - padding_length, len(data)):
        if data[i] != padding_length:
            raise ValueError("Invalid padding byte")
    
    return data[:-padding_length]

if __name__ == "__main__":
    encrypted_data = encrypt_data("Input data here")
    print("Encrypted Data:", encrypted_data)
