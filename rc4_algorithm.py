import os
import base64
from hashlib import pbkdf2_hmac
from encryption_decryption_interface import EncryptionDecryptionInterface
class RC4Algorithm(EncryptionDecryptionInterface):
    def __init__(self):
        self.key = None

    def encrypt_bytes(self, data, password):
        salt = os.urandom(16)

        self.key = self._derive_key(password, salt)

        encrypted_data = self._rc4_encrypt(data, self.key)
        print(salt.hex())
        return salt.hex(), encrypted_data

    def decrypt_bytes(self, encrypted_key, encrypted_data, password):


        salt = bytes.fromhex(encrypted_key[0])
        print(salt)
        ciphertext = encrypted_data

        self.key = self._derive_key(password, salt)

        decrypted_data = self._rc4_encrypt(ciphertext, self.key)
        return decrypted_data

    def _derive_key(self, password, salt):
        return pbkdf2_hmac('sha256', password.encode(), salt, 100000)

    def _rc4_encrypt(self, data, key):
        S = list(range(256))
        j = 0

        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]

        i = 0
        j = 0
        result = bytearray()

        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            result.append(byte ^ K)

        return bytes(result)
