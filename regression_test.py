import sys
import unittest
import string
import random
import os
from connector import Connector
import logging
logging.basicConfig(level=logging.DEBUG)


class TestConnectorEncryptionDecryption(unittest.TestCase):
    def setUp(self):
        self.connector = Connector()
        self.connector.select_algorithm("AES")
        self.password = "StrongPassword123!"
        self.test_file_data = [
            ["testfile.txt", b"Sample data to be encrypted and decrypted."]
        ]

    def generate_random_password(self):
        return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=16))

    def test_encrypt_and_decrypt(self):
        encrypt_errors, encrypted_files = self.connector.encrypt_files(self.test_file_data, self.password)

        self.assertEqual(encrypt_errors, "", f"Encryption errors occurred: {encrypt_errors}")
        self.assertTrue(len(encrypted_files) > 0, "No files were encrypted.")

        decrypt_errors, decrypted_files = self.connector.decrypt_files(encrypted_files, self.password)

        self.assertEqual(decrypt_errors, "", f"Decryption errors occurred: {decrypt_errors}")
        self.assertTrue(len(decrypted_files) > 0, "No files were decrypted.")
        original_data = self.test_file_data[0][1]
        decrypted_data = decrypted_files[0][1]
        self.assertEqual(original_data, decrypted_data, "Decrypted data does not match the original data.")

    def test_encrypt_files(self):
        folder_path = "algorithms_history/"
        files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f)) and f.endswith(".bin")]
        connector = Connector()
        sys.stdout.write(f"Files found: {files}\n")
        for file in files:
            file_path = os.path.join(folder_path, file)
            try:
                with open(file_path, "rb") as file1:
                    file_bytes = file1.read()
                err, dec_files = connector.decrypt_files([[file_path, file_bytes]], '')
                self.assertGreater(len(dec_files), 0, f"Decryption result for {file} is empty.")
            except Exception as e:
                self.fail(f"Error during decryption {file}: {str(e)} with algorithm "+str(connector.algorithm))


if __name__ == '__main__':
    unittest.main()