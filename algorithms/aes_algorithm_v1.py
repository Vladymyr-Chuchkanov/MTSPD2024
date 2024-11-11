from hashlib import pbkdf2_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from encryption_decryption_interface import EncryptionDecryptionInterface


import os


class AESAlgorithmV1(EncryptionDecryptionInterface):
    def __init__(self):
        self.key = None
        self.default_password = "Shyf43U4!w[;"

    def encrypt_bytes(self, file_bytes, password):
        if password == "":
            password = "Shyf43U4!w[;"
        salt = os.urandom(16)
        iterations = 20000  # change! iterations = 10000
        self.key = pbkdf2_hmac('sha1', password.encode('utf-8'), salt, iterations, dklen=32)

        nonce = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(file_bytes) + encryptor.finalize()
        tag = encryptor.tag

        encrypted_keys = f"{nonce.hex()}\n{tag.hex()}\n{salt.hex()}"

        return encrypted_keys, ciphertext

    def decrypt_bytes(self, encrypted_keys, encrypted_data, password):
        if password == "":
            password = "Shyf43U4!w[;"
        nonce = encrypted_keys[0]
        tag = encrypted_keys[1]
        salt = encrypted_keys[2]

        nonce = bytes.fromhex(nonce)
        tag = bytes.fromhex(tag)
        salt = bytes.fromhex(salt)
        iterations = 20000  # change! iterations = 10000
        self.key = pbkdf2_hmac('sha1', password.encode('utf-8'), salt, iterations, dklen=32)

        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
        return plaintext