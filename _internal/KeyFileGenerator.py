from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os


class KeyFileGenerator:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @staticmethod
    def generate_keys(password, storage_path):
        key = RSA.generate(2048)

        private_key = key.export_key(pkcs=8)
        public_key = key.publickey().export_key()

        KeyFileGenerator.encrypt_file(
            private_key, password, os.path.join(storage_path, "private.key.enc")
        )
        KeyFileGenerator.encrypt_file(
            public_key, password, os.path.join(storage_path, "public.key.enc")
        )

    @staticmethod
    def encrypt_file(key_data, password, output_file):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = kdf.derive(password.encode())

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(key_data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        with open(output_file, "wb") as f:
            f.write(salt + iv + encrypted_data)
