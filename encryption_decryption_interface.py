from abc import ABC, abstractmethod


class EncryptionDecryptionInterface(ABC):
    @abstractmethod
    def encrypt_bytes(self, files_data, password):
        pass

    @abstractmethod
    def decrypt_bytes(self, keys, files_data, password):
        pass